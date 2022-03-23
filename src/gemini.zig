const std = @import("std");
const network = @import("network");
const uri = @import("uri");
const ssl = @import("bearssl");

const TrustLevel = enum {
    all,
    ca,
    tofu,
};

fn convertHexToArray(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if ((input.len % 2) != 0)
        return error.StringMustHaveEvenLength;

    var data = try allocator.alloc(u8, input.len / 2);
    errdefer allocator.free(data);

    var i: usize = 0;
    while (i < input.len) : (i += 2) {
        data[i / 2] = try std.fmt.parseInt(u8, input[i..][0..2], 16);
    }
    return data;
}

fn parsePublicKeyFile(allocator: std.mem.Allocator, file: std.fs.File) !ssl.PublicKey {
    const instream = file.reader();

    // RSA is supported up to 4096 bits, so 512 byte.
    var backing_buffer: [520]u8 = undefined;

    const type_id = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;

    var key = ssl.PublicKey{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .key = undefined,
        .usages = null,
    };
    errdefer key.deinit();

    if (std.mem.eql(u8, type_id, "RSA")) {
        var rsa = ssl.PublicKey.KeyStore.RSA{
            .n = undefined,
            .e = undefined,
        };

        const n_string = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;
        rsa.n = try convertHexToArray(&key.arena.allocator, n_string);

        const e_string = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;
        rsa.e = try convertHexToArray(&key.arena.allocator, e_string);

        key.key = ssl.PublicKey.KeyStore{
            .rsa = rsa,
        };
    } else if (std.mem.eql(u8, type_id, "EC")) {
        var ec = ssl.PublicKey.KeyStore.EC{
            .curve = undefined,
            .q = undefined,
        };

        const curve_string = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;
        ec.curve = try std.fmt.parseInt(c_int, curve_string, 16);

        const q_string = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;

        ec.q = try convertHexToArray(&key.arena.allocator, q_string);
        key.key = ssl.PublicKey.KeyStore{
            .ec = ec,
        };
    } else {
        return error.UnsupportedKeyType;
    }

    const usages_text = (try instream.readUntilDelimiterOrEof(&backing_buffer, '\n')) orelse return error.InvalidFormat;
    key.usages = try std.fmt.parseInt(c_uint, usages_text, 16);

    return key;
}

// gemini://gemini.circumlunar.space/docs/spec-spec.txt
// gemini://gemini.conman.org/test/torture/0000

// /*
// * Check whether we closed properly or not. If the engine is
// * closed, then its error status allows to distinguish between
// * a normal closure and a SSL error.
// *
// * If the engine is NOT closed, then this means that the
// * underlying network socket was closed or failed in some way.
// * Note that many Web servers out there do not properly close
// * their SSL connections (they don't send a close_notify alert),
// * which will be reported here as "socket closed without proper
// * SSL termination".
// */
//
// if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
//   int err;
//   err = br_ssl_engine_last_error(&sc.eng);
//   if (err == 0) {
//     fprintf(stderr, "closed.\n");
//     return EXIT_SUCCESS;
//   } else {
//     fprintf(stderr, "SSL error %d\n", err);
//     return EXIT_FAILURE;
//   }
// } else {
//   fprintf(stderr,
//     "socket closed without proper SSL termination\n");
//   return EXIT_FAILURE;
// }

/// Response from the server. Must call free to release the resources in the response.
pub const Response = struct {
    const Self = @This();

    /// Contains the response from the server
    content: Content,

    /// Contains the certificate chain returned by the server.
    certificate_chain: []ssl.DERCertificate,

    /// The public key of the server extracted from the certificate chain
    public_key: ssl.PublicKey,

    /// Releases the stored resources in the response.
    pub fn free(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_chain);
        self.public_key.deinit();

        switch (self.content) {
            .untrustedCertificate => {},
            .badSignature => {},
            .input => |input| {
                allocator.free(input.prompt);
            },
            .redirect => |redir| {
                allocator.free(redir.target);
            },
            .success => |body| {
                allocator.free(body.mime);
                allocator.free(body.data);
            },
            .temporaryFailure, .permanentFailure => |fail| {
                allocator.free(fail.message);
            },
            .clientCertificateRequired => |cert| {
                allocator.free(cert.message);
            },
        }
    }

    const Content = union(enum) {
        /// When the server is not known or trusted yet, it just returns a nil value showing that
        /// the server could be reached, but we don't trust it.
        untrustedCertificate: void,

        /// The server responded with a different signature than the one stored in the trust store.
        badSignature: void,

        /// Status Code = 1*
        input: Input,

        /// Status Code = 2*
        success: Body,

        /// Status Code = 3*
        redirect: Redirect,

        /// Status Code = 4*
        temporaryFailure: Failure,

        /// Status Code = 5*
        permanentFailure: Failure,

        /// Status Code = 6*
        clientCertificateRequired: CertificateAction,
    };

    pub const Input = struct {
        prompt: []const u8,
    };

    pub const Body = struct {
        mime: []const u8,
        data: []const u8,
        isEndOfClientCertificateSession: bool,
    };

    pub const Redirect = struct {
        pub const Type = enum { permanent, temporary };

        target: []const u8,
        type: Type,
    };

    pub const Failure = struct {
        pub const Type = enum {
            unspecified,
            serverUnavailable,
            cgiError,
            proxyError,
            slowDown,
            notFound,
            gone,
            proxyRequestRefused,
            badRequest,
        };

        type: Type,
        message: []const u8,
    };

    pub const CertificateAction = struct {
        pub const Type = enum {
            unspecified,
            transientCertificateRequested,
            authorisedCertificateRequired,
            certificateNotAccepted,
            futureCertificateRejected,
            expiredCertificateRejected,
        };

        type: Type,
        message: []const u8,
    };
};
pub const ResponseType = std.meta.TagType(Response.Content);

const empty_trust_anchor_set = ssl.TrustAnchorCollection.init(std.testing.failing_allocator);

pub const RequestOptions = struct {
    memory_limit: usize = 100 * mega_bytes,
    verification: RequestVerification,
};

pub const RequestVerification = union(enum) {
    trust_anchor: ssl.TrustAnchorCollection,
    public_key: ssl.PublicKey,
    none: void,
};

/// Performs a raw request without any redirection handling or somilar.
/// Either errors out when the request is malformed or returns a response from the server.
pub fn requestRaw(allocator: std.mem.Allocator, url: []const u8, options: RequestOptions) !Response {
    if (url.len > 1024)
        return error.InvalidUrl;

    var temp_allocator_buffer: [5000]u8 = undefined;
    var temp_allocator_state = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
    const temp_allocator = temp_allocator_state.allocator();

    const parsed_url = uri.parse(url) catch return error.InvalidUrl;

    if (parsed_url.scheme == null)
        return error.InvalidUrl;
    if (!std.mem.eql(u8, parsed_url.scheme.?, "gemini"))
        return error.UnsupportedScheme;

    if (parsed_url.host == null)
        return error.MissingAuthority;

    const hostname_z = try temp_allocator.dupeZ(u8, parsed_url.host.?);

    var socket = try network.connectToHost(temp_allocator, hostname_z, parsed_url.port orelse 1965, .tcp);
    defer socket.close();

    var x509 = switch (options.verification) {
        .trust_anchor => |list| CertificateValidator.initTrustAnchor(allocator, list),
        .none => CertificateValidator.initTrustAll(allocator),
        .public_key => |key| CertificateValidator.initPubKey(allocator, key),
    };
    defer x509.deinit();

    var ssl_context = ssl.Client.init(x509.getEngine());

    ssl_context.relocate();
    try ssl_context.reset(hostname_z, false);

    // std.log.warn("ssl initialized.\n", .{});

    var tcp_in = socket.reader();
    var tcp_out = socket.writer();

    var ssl_stream = ssl.initStream(ssl_context.getEngine(), &tcp_in, &tcp_out);
    defer if (ssl_stream.close()) {} else |err| {
        std.log.warn("error when closing the stream: {}\n", .{err});
    };

    const in = ssl_stream.reader();
    const out = ssl_stream.writer();

    var work_buf: [1500]u8 = undefined;

    const request_str = try std.fmt.bufPrint(&work_buf, "{s}\r\n", .{url});

    const request_response = out.writeAll(request_str);

    var response = Response{
        .certificate_chain = undefined,
        .public_key = undefined,
        .content = undefined,
    };

    response.public_key = try x509.extractPublicKey(allocator);
    errdefer response.public_key.deinit();

    response.certificate_chain = x509.certificates.toOwnedSlice();
    errdefer {
        for (response.certificate_chain) |cert| {
            cert.deinit();
        }
        //allocator.free(response.certificate_chain);
    }

    request_response catch |err| switch (err) {
        error.X509_NOT_TRUSTED => {
            response.content = Response.Content{ .untrustedCertificate = {} };
            return response;
        },
        error.BAD_SIGNATURE => {
            response.content = Response.Content{ .badSignature = {} };
            return response;
        },
        error.X509_BAD_SERVER_NAME => return error.BadServerName,
        else => return err,
    };
    try ssl_stream.flush();

    const response_header = if (try in.readUntilDelimiterOrEof(&work_buf, '\n')) |buf|
        buf
    else
        return error.InvalidResponse;

    if (response_header.len < 3)
        return error.InvalidResponse;

    if (response_header[response_header.len - 1] != '\r') // not delimited by \r\n
        return error.InvalidResponse;

    if (!std.ascii.isDigit(response_header[0])) // not a number
        return error.InvalidResponse;

    if (!std.ascii.isDigit(response_header[1])) // not a number
        return error.InvalidResponse;

    const meta = std.mem.trim(u8, response_header[2..], " \t\r\n");
    if (meta.len > 1024)
        return error.InvalidResponse;

    // std.log.warn("handshake complete: {}\n", .{response});

    response.content = switch (response_header[0]) { // primary status code
        '1' => blk: { // INPUT
            var prompt = try allocator.dupe(u8, meta);
            errdefer allocator.free(prompt);

            break :blk Response.Content{
                .input = Response.Input{
                    .prompt = prompt,
                },
            };
        },
        '2' => blk: { // SUCCESS
            var mime = try allocator.dupe(u8, meta);
            errdefer allocator.free(mime);

            var data = try in.readAllAlloc(allocator, options.memory_limit);

            break :blk Response.Content{
                .success = Response.Body{
                    .mime = mime,
                    .data = data,
                    .isEndOfClientCertificateSession = (response_header[1] == '1'), // check for 21
                },
            };
        },
        '3' => blk: { // REDIRECT
            var target = try allocator.dupe(u8, meta);
            errdefer allocator.free(target);

            break :blk Response.Content{
                .redirect = Response.Redirect{
                    .target = target,
                    .type = if (response_header[1] == '1')
                        Response.Redirect.Type.permanent
                    else
                        Response.Redirect.Type.temporary,
                },
            };
        },
        '4' => blk: { // TEMPORARY FAILURE
            var message = try allocator.dupe(u8, meta);
            errdefer allocator.free(message);

            break :blk Response.Content{
                .temporaryFailure = Response.Failure{
                    .type = switch (response_header[1]) {
                        '1' => Response.Failure.Type.serverUnavailable,
                        '2' => Response.Failure.Type.cgiError,
                        '3' => Response.Failure.Type.proxyError,
                        '4' => Response.Failure.Type.slowDown,
                        else => Response.Failure.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        '5' => blk: { // PERMANENT FAILURE
            var message = try allocator.dupe(u8, meta);
            errdefer allocator.free(message);

            break :blk Response.Content{
                .permanentFailure = Response.Failure{
                    .type = switch (response_header[1]) {
                        '1' => Response.Failure.Type.notFound,
                        '2' => Response.Failure.Type.gone,
                        '3' => Response.Failure.Type.proxyRequestRefused,
                        '4' => Response.Failure.Type.badRequest,
                        else => Response.Failure.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        '6' => blk: { // CLIENT CERTIFICATE REQUIRED
            var message = try allocator.dupe(u8, meta);
            errdefer allocator.free(message);

            break :blk Response.Content{
                .clientCertificateRequired = Response.CertificateAction{
                    .type = switch (response_header[1]) {
                        '1' => Response.CertificateAction.Type.transientCertificateRequested,
                        '2' => Response.CertificateAction.Type.authorisedCertificateRequired,
                        '3' => Response.CertificateAction.Type.certificateNotAccepted,
                        '4' => Response.CertificateAction.Type.futureCertificateRejected,
                        '5' => Response.CertificateAction.Type.expiredCertificateRejected,
                        else => Response.CertificateAction.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        else => return error.UnknownStatusCode,
    };

    return response;
}

/// Processes redirects and such
pub fn request(allocator: std.mem.Allocator, url: []const u8, options: RequestOptions) !Response {
    var url_buffer = std.heap.ArenaAllocator.init(allocator);
    defer url_buffer.deinit();

    var next_url = url;

    var redirection_count: usize = 0;
    while (redirection_count < 5) : (redirection_count += 1) {
        var response = try requestRaw(allocator, next_url, options);

        switch (response.content) {
            .redirect => |redirection| {
                std.log.warn("iteration {} → {s}\n", .{
                    redirection_count,
                    redirection.target,
                });

                next_url = try url_buffer.allocator().dupe(u8, redirection.target);
                response.free(allocator);
            },
            else => return response,
        }
    }
    return error.TooManyRedirections;
}

const kibi_bytes = 1024;
const mebi_bytes = 1024 * 1024;
const gibi_bytes = 1024 * 1024 * 1024;

const kilo_bytes = 1000;
const mega_bytes = 1000_000;
const giga_bytes = 1000_000_000;

/// Custom x509 engine that uses the minimal engine and ignores missing trust.
/// First step in TOFU direction
pub const CertificateValidator = struct {
    const Self = @This();

    const Options = struct {
        ignore_untrusted: bool = false,
        ignore_hostname_mismatch: bool = false,
    };

    const class = ssl.c.br_x509_class{
        .context_size = @sizeOf(Self),
        .start_chain = start_chain,
        .start_cert = start_cert,
        .append = append,
        .end_cert = end_cert,
        .end_chain = end_chain,
        .get_pkey = get_pkey,
    };

    vtable: [*c]const ssl.c.br_x509_class = &class,
    x509: union(enum) {
        minimal: ssl.c.br_x509_minimal_context,
        known_key: ssl.c.br_x509_knownkey_context,
    },

    allocator: std.mem.Allocator,
    certificates: std.ArrayList(ssl.DERCertificate),

    current_cert_valid: bool = undefined,
    temp_buffer: FixedGrowBuffer(u8, 2048) = undefined,

    server_name: ?[]const u8 = null,

    options: Options = Options{},

    fn initTrustAnchor(allocator: std.mem.Allocator, list: ssl.TrustAnchorCollection) Self {
        return Self{
            .x509 = .{
                .minimal = ssl.x509.Minimal.init(list).engine,
            },
            .allocator = allocator,
            .certificates = std.ArrayList(ssl.DERCertificate).init(allocator),
        };
    }
    fn initTrustAll(allocator: std.mem.Allocator) Self {
        return Self{
            .x509 = .{
                .minimal = ssl.x509.Minimal.init(empty_trust_anchor_set).engine,
            },
            .allocator = allocator,
            .certificates = std.ArrayList(ssl.DERCertificate).init(allocator),
            .options = .{
                .ignore_untrusted = true,
            },
        };
    }
    fn initPubKey(allocator: std.mem.Allocator, key: ssl.PublicKey) Self {
        return Self{
            .x509 = .{
                .known_key = ssl.x509.KnownKey.init(key, true, true).engine,
            },
            .allocator = allocator,
            .certificates = std.ArrayList(ssl.DERCertificate).init(allocator),
            .options = .{
                .ignore_untrusted = true,
            },
        };
    }

    pub fn deinit(self: Self) void {
        for (self.certificates.items) |cert| {
            cert.deinit();
        }
        self.certificates.deinit();

        if (self.server_name) |name| {
            self.allocator.free(name);
        }
    }

    pub fn setToKnownKey(self: *Self, key: ssl.PublicKey) void {
        self.x509.x509_known_key = ssl.c.br_x509_knownkey_context{
            .vtable = &ssl.c.br_x509_knownkey_vtable,
            .pkey = key.toX509(),
            .usages = (key.usages orelse 0) | ssl.c.BR_KEYTYPE_KEYX | ssl.c.BR_KEYTYPE_SIGN, // always allow a stored key for key-exchange
        };
    }

    fn returnTypeOf(comptime Class: type, comptime name: std.meta.FieldEnum(Class)) type {
        return @typeInfo(std.meta.Child(std.meta.fieldInfo(Class, name).field_type)).Fn.return_type.?;
    }

    fn virtualCall(object: anytype, comptime name: std.meta.FieldEnum(@TypeOf(object.vtable.?.*)), args: anytype) returnTypeOf(ssl.c.br_x509_class, name) {
        return @call(.{}, @field(object.vtable.?.*, @tagName(name)).?, .{&object.vtable} ++ args);
    }

    fn proxyCall(self: anytype, comptime name: @TypeOf(.literal), args: anytype) returnTypeOf(ssl.c.br_x509_class, name) {
        return switch (self.x509) {
            .minimal => |*m| virtualCall(m, name, args),
            .known_key => |*k| virtualCall(k, name, args),
        };
    }

    fn fromPointer(ctx: anytype) if (@typeInfo(@TypeOf(ctx)).Pointer.is_const) *const Self else *Self {
        return if (@typeInfo(@TypeOf(ctx)).Pointer.is_const)
            return @fieldParentPtr(Self, "vtable", @ptrCast(*const [*c]const ssl.c.br_x509_class, ctx))
        else
            return @fieldParentPtr(Self, "vtable", @ptrCast(*[*c]const ssl.c.br_x509_class, ctx));
    }

    fn start_chain(ctx: [*c][*c]const ssl.c.br_x509_class, server_name: [*c]const u8) callconv(.C) void {
        const self = fromPointer(ctx);
        // std.log.warn("start_chain({0}, {1})\n", .{
        //     ctx,
        //     std.mem.span(server_name),
        // });

        self.proxyCall(.start_chain, .{server_name});

        for (self.certificates.items) |cert| {
            cert.deinit();
        }
        self.certificates.shrinkRetainingCapacity(0);

        if (self.server_name) |name| {
            self.allocator.free(name);
        }
        self.server_name = null;

        self.server_name = self.allocator.dupe(u8, std.mem.span(server_name)) catch null;
    }

    fn start_cert(ctx: [*c][*c]const ssl.c.br_x509_class, length: u32) callconv(.C) void {
        const self = fromPointer(ctx);
        // std.log.warn("start_cert({0}, {1})\n", .{
        //     ctx,
        //     length,
        // });
        self.proxyCall(.start_cert, .{length});

        self.temp_buffer = FixedGrowBuffer(u8, 2048).init();
        self.current_cert_valid = true;
    }

    fn append(ctx: [*c][*c]const ssl.c.br_x509_class, buf: [*c]const u8, len: usize) callconv(.C) void {
        const self = fromPointer(ctx);
        // std.log.warn("append({0}, {1}, {2})\n", .{
        //     ctx,
        //     buf,
        //     len,
        // });
        self.proxyCall(.append, .{ buf, len });

        self.temp_buffer.write(buf[0..len]) catch {
            std.log.warn("too much memory!\n", .{});
            self.current_cert_valid = false;
        };
    }

    fn end_cert(ctx: [*c][*c]const ssl.c.br_x509_class) callconv(.C) void {
        const self = fromPointer(ctx);
        // std.log.warn("end_cert({})\n", .{
        //     ctx,
        // });
        self.proxyCall(.end_cert, .{});

        if (self.current_cert_valid) {
            const cert = ssl.DERCertificate{
                .allocator = self.allocator,
                .data = self.allocator.dupe(u8, self.temp_buffer.constSpan()) catch return, // sad, but no other choise
            };
            errdefer cert.deinit();

            self.certificates.append(cert) catch return;
        }
    }

    fn end_chain(ctx: [*c][*c]const ssl.c.br_x509_class) callconv(.C) c_uint {
        const self = fromPointer(ctx);

        const err = self.proxyCall(.end_chain, .{});
        // std.log.warn("end_chain({}) → {}\n", .{
        //     ctx,
        //     err,
        // });

        // std.log.warn("Received {} certificates for {}!\n", .{
        //     self.certificates.items.len,
        //     self.server_name,
        // });

        // Patch the error code and just accept in case of ignoring this error.
        if (err == ssl.c.BR_ERR_X509_NOT_TRUSTED and self.options.ignore_untrusted) {
            return 0;
        }

        // Patch the error code and just accept in case of ignoring this error.
        if (err == ssl.c.BR_ERR_X509_BAD_SERVER_NAME and self.options.ignore_hostname_mismatch) {
            return 0;
        }

        return err;
    }

    fn get_pkey(ctx: [*c]const [*c]const ssl.c.br_x509_class, usages: [*c]c_uint) callconv(.C) [*c]const ssl.c.br_x509_pkey {
        const self = fromPointer(ctx);

        const pkey = self.proxyCall(.get_pkey, .{usages});
        // std.log.warn("get_pkey({}, {}) → {}\n", .{
        //     ctx,
        //     usages,
        //     pkey,
        // });
        return pkey;
    }

    fn saveCertificates(self: Self, folder: []const u8) !void {
        var trust_store_dir = try std.fs.cwd().openDir("trust-store", .{ .access_sub_paths = true, .iterate = false });
        defer trust_store_dir.close();

        trust_store_dir.makeDir(folder) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var server_dir = try trust_store_dir.openDir(folder, .{ .access_sub_paths = true, .iterate = false });
        defer server_dir.close();

        for (self.certificates.items) |cert, index| {
            var name_buf: [64]u8 = undefined;
            var name = try std.fmt.bufPrint(&name_buf, "cert-{}.der", .{index});

            var file = try server_dir.createFile(name, .{ .exclusive = false });
            defer file.close();

            try file.writeAll(cert.data);
        }
    }

    pub fn extractPublicKey(self: Self, allocator: std.mem.Allocator) !ssl.PublicKey {
        var usages: c_uint = 0;
        const pkey = self.proxyCall(.get_pkey, .{usages});
        std.debug.assert(pkey != null);
        var key = try ssl.PublicKey.fromX509(allocator, pkey.*);
        key.usages = usages;
        return key;
    }

    fn getEngine(self: *Self) *[*c]const ssl.c.br_x509_class {
        return &self.vtable;
    }
};

fn FixedGrowBuffer(comptime T: type, comptime max_len: usize) type {
    return struct {
        const Self = @This();

        offset: usize,
        buffer: [max_len]T,

        pub fn init() Self {
            return Self{
                .offset = 0,
                .buffer = undefined,
            };
        }

        pub fn reset(self: *Self) void {
            self.offset = 0;
        }

        pub fn write(self: *Self, data: []const T) error{OutOfMemory}!void {
            if (self.offset + data.len > self.buffer.len)
                return error.OutOfMemory;
            std.mem.copy(T, self.buffer[self.offset..], data);
            self.offset += data.len;
        }

        pub fn span(self: *Self) []T {
            return self.buffer[0..self.offset];
        }

        pub fn constSpan(self: *Self) []const T {
            return self.buffer[0..self.offset];
        }
    };
}

// tests

test "loading system certs" {
    var file = try std.fs.cwd().openFile("/etc/ssl/cert.pem", .{ .read = true, .write = false });
    defer file.close();

    const pem_text = try file.reader().readAllAlloc(std.testing.allocator, 1 << 20); // 1 MB
    defer std.testing.allocator.free(pem_text);

    var trust_anchors = ssl.TrustAnchorCollection.init(std.testing.allocator);
    defer trust_anchors.deinit();

    try trust_anchors.appendFromPEM(pem_text);
}

const TestExpection = union(enum) {
    response: ResponseType,
    err: anyerror,
};

fn runRawTestRequest(url: []const u8, expected_response: TestExpection) !void {
    if (requestRaw(std.testing.allocator, url, .{
        .verification = .none,
    })) |response| {
        defer response.free(std.testing.allocator);

        if (expected_response != .response) {
            std.log.warn("Expected error, but got {}\n", .{@as(ResponseType, response.content)});
            return error.UnexpectedResponse;
        }

        if (response.content != expected_response.response) {
            std.log.warn("Expected {}, but got {}\n", .{ expected_response.response, @as(ResponseType, response.content) });
            return error.UnexpectedResponse;
        }
    } else |err| {
        if (expected_response != .err) {
            std.log.warn("Expected {}, but got error {}\n", .{ expected_response.response, err });
            return error.UnexpectedResponse;
        }
        if (err != expected_response.err) {
            std.log.warn("Expected error {}, but got error {}\n", .{ expected_response.err, err });
            return error.UnexpectedResponse;
        }
    }
}

fn runTestRequest(url: []const u8, expected_response: TestExpection) !void {
    if (request(std.testing.allocator, url, .{
        .verification = .none,
    })) |response| {
        defer response.free(std.testing.allocator);

        if (expected_response != .response) {
            std.log.warn("Expected error, but got {}\n", .{@as(ResponseType, response.content)});
            return error.UnexpectedResponse;
        }

        if (response.content != expected_response.response) {
            std.log.warn("Expected {}, but got {}\n", .{ expected_response.response, @as(ResponseType, response.content) });
            return error.UnexpectedResponse;
        }
    } else |err| {
        if (expected_response != .err) {
            std.log.warn("Expected {}, but got error {}\n", .{ expected_response.response, err });
            return error.UnexpectedResponse;
        }
        if (err != expected_response.err) {
            std.log.warn("Expected error {}, but got error {}\n", .{ expected_response.err, err });
            return error.UnexpectedResponse;
        }
    }
}

// Test some API invariants:

test "invalid url scheme" {
    if (requestRaw(std.testing.allocator, "madeup+uri://lolwat/wellheck", RequestOptions{
        .verification = .none,
    })) |val| {
        val.free(std.testing.allocator);
    } else |err| {
        switch (err) {
            error.UnsupportedScheme => return, // this is actually the success vector!
            else => return err,
        }
    }
}

// Test several different responses

test "10 INPUT: query gus" {
    try runRawTestRequest("gemini://gus.guru/search", .{ .response = .input });
}

test "51 PERMANENT FAILURE: query mozz.us" {
    try runRawTestRequest("gemini://mozz.us/topkek", .{ .response = .permanentFailure });
}

// Run test suite against conmans torture suit

// Index page
test "torture suite/raw (0000)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0000", .{ .response = .success });
}

// Redirect-continous temporary redirects
test "torture suite/raw (0022)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell/", .{ .response = .redirect });
}

// Redirect-continous permanent redirects
test "torture suite/raw (0023)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell2/", .{ .response = .redirect });
}

// Redirect-continous random temporary or permanent redirects
test "torture suite/raw (0024)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell3/", .{ .response = .redirect });
}

// Redirect-continous temporary redirects to itself
test "torture suite/raw (0025)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell4", .{ .response = .redirect });
}

// Redirect-continous permanent redirects to itself
test "torture suite/raw (0026)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell5", .{ .response = .redirect });
}

// Redirect-to a non-gemini link
test "torture suite/raw (0027)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/redirhell6", .{ .response = .redirect });
}

// Status-undefined status code
test "torture suite/raw (0034)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0034a", .{ .err = error.UnknownStatusCode });
}

// Status-undefined success status code
test "torture suite/raw (0035)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0035a", .{ .response = .success });
}

// Status-undefined redirect status code
test "torture suite/raw (0036)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0036a", .{ .response = .redirect });
}

// Status-undefined temporary status code
test "torture suite/raw (0037)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0037a", .{ .response = .temporaryFailure });
}

// Status-undefined permanent status code
test "torture suite/raw (0038)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0038a", .{ .response = .permanentFailure });
}

// Status-one digit status code
test "torture suite/raw (0039)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0039a", .{ .err = error.InvalidResponse });
}

// Status-complete blank line
test "torture suite/raw (0040)" {
    try runRawTestRequest("gemini://gemini.conman.org/test/torture/0040a", .{ .err = error.InvalidResponse });
}

// Run test suite against conmans torture suit

// Index page
test "torture suite (0000)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0000", .{ .response = .success });
}

// Redirect-continous temporary redirects
test "torture suite (0022)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell/", .{ .err = error.TooManyRedirections });
}

// Redirect-continous permanent redirects
test "torture suite (0023)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell2/", .{ .err = error.TooManyRedirections });
}

// Redirect-continous random temporary or permanent redirects
test "torture suite (0024)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell3/", .{ .err = error.TooManyRedirections });
}

// Redirect-continous temporary redirects to itself
test "torture suite (0025)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell4", .{ .err = error.TooManyRedirections });
}

// Redirect-continous permanent redirects to itself
test "torture suite (0026)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell5", .{ .err = error.TooManyRedirections });
}

// Redirect-to a non-gemini link
test "torture suite (0027)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell6", .{ .err = error.UnsupportedScheme });
}

// Status-undefined status code
test "torture suite (0034)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0034a", .{ .err = error.UnknownStatusCode });
}

// Status-undefined success status code
test "torture suite (0035)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0035a", .{ .response = .success });
}

// Status-undefined redirect status code
test "torture suite (0036)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0036a", .{ .response = .success });
}

// Status-undefined temporary status code
test "torture suite (0037)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0037a", .{ .response = .temporaryFailure });
}

// Status-undefined permanent status code
test "torture suite (0038)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0038a", .{ .response = .permanentFailure });
}

// Status-one digit status code
test "torture suite (0039)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0039a", .{ .err = error.InvalidResponse });
}

// Status-complete blank line
test "torture suite (0040)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0040a", .{ .err = error.InvalidResponse });
}

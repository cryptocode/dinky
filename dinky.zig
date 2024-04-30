const sockaddr_in_t = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8 = [_]u8{0} ** 8,
};

var argc_argv_ptr: [*]usize = undefined;

// Extract argc and argv and call `startServer()`. Note that this function is
// marked naked, which means we must call the startServer function from assembly.
export fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\ xorl %%ebp, %%ebp
        \\ movq %%rsp, %[argc_argv_ptr]
        : [argc_argv_ptr] "=m" (argc_argv_ptr),
        : [startServer] "X" (&startServer),
    );
}

fn startServer() callconv(.C) noreturn {
    const argc = argc_argv_ptr[0];
    const argv = @as([*][*:0]const u8, @ptrCast(argc_argv_ptr + 1));

    if (argc != 4) {
        usage();
    }

    const port = u16fromString(argv[1]);
    const filename = argv[2];
    const filename_len = strnlen(filename, 256);
    const content_type = argv[3];
    const content_type_len = strnlen(content_type, 256);

    if (port == 0 or filename_len == 0 or content_type_len == 0) {
        usage();
    }

    httpd(port, filename, content_type[0..content_type_len]) catch {
        note("Server error\n");
    };

    exit(0);
}

/// Start the http server and listen for client connection.
fn httpd(port: u16, filename: [*:0]const u8, content_type: []const u8) !void {

    // Create a socket of type AF_INET, SOCK_STREAM, IPPROTO_TCP
    const sock_fd = try socket(2, 1, 6);

    var addr: sockaddr_in_t = .{
        .sin_family = 2,
        .sin_addr = 0,
        .sin_port = (port << 8 & 0xff00) | (port >> 8 & 0x00ff),
    };

    try bind(sock_fd, &addr, @sizeOf(@TypeOf(addr)));
    try listen(sock_fd, 10);

    while (true) {
        const client_fd = try accept(sock_fd, null, 0);
        const pid = try fork();
        if (pid == 0) {
            const page_fd = try open(filename, 0);
            const content_size: usize = try getFileSize(page_fd);
            var len_buf: [20]u8 = undefined;
            const len_slice = itoa(@intCast(content_size), &len_buf);

            _ = try writeSlice(client_fd, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-length: ");
            _ = try writeSlice(client_fd, len_slice);
            _ = try writeSlice(client_fd, "\r\nContent-type: ");
            _ = try writeSlice(client_fd, content_type);
            _ = try writeSlice(client_fd, "\r\n\r\n");

            // Write the HTML file to the client
            try sendFile(client_fd, page_fd, content_size);

            // Clean up and exit child process
            _ = try close(page_fd);
            _ = try close(client_fd);
            exit(0);
        }
    }
}

/// Print program usage
fn usage() void {
    note("Usage:\n    ./dinky 8088 index.html text/html\n");
    exit(1);
}

inline fn note(msg: []const u8) void {
    print(1, msg.ptr, msg.len);
}

inline fn read(fd: usize, buf: [*]u8, count: usize) !usize {
    const res = syscall(0, fd, @intFromPtr(buf), count, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

fn printSlice(fd: usize, buf: []const u8) void {
    print(fd, buf.ptr, buf.len);
}

fn print(fd: usize, buf: [*]const u8, count: usize) void {
    _ = write(fd, buf, count) catch {};
}

fn writeSlice(fd: usize, buf: []const u8) !usize {
    return try write(fd, buf.ptr, buf.len);
}

fn writeAll(fd: usize, buf: [*]const u8, count: usize) !void {
    var total: usize = 0;
    while (total < count) {
        const written = try write(fd, buf[total..], count - total);
        if (written == -1) return error.WriteAllError;
        total += written;
    }
}

inline fn write(fd: usize, buf: [*]const u8, count: usize) !usize {
    const res = syscall(1, fd, @intFromPtr(buf), count, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

fn socket(domain: usize, socket_type: usize, protocol: usize) !usize {
    const res = syscall(41, domain, socket_type, protocol, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

inline fn bind(sock: usize, sock_address: *sockaddr_in_t, address_len: usize) !void {
    const res = syscall(49, sock, @intFromPtr(sock_address), address_len, 0, 0, 0);
    if (res < 0) return error.NetworkError;
}

fn listen(sock: usize, backlog: usize) !void {
    const res = syscall(50, sock, backlog, 0, 0, 0, 0);
    if (res < 0) return error.NetworkError;
}

fn accept(sock: usize, address: ?*sockaddr_in_t, address_len: usize) !usize {
    const res = syscall(43, sock, if (address) |addr| @intFromPtr(addr) else 0, address_len, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

inline fn close(fd: usize) !usize {
    const res = syscall(3, fd, 0, 0, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

inline fn fork() !usize {
    const res = syscall(57, 0, 0, 0, 0, 0, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

inline fn setsockopt(sock: usize, level: usize, option_name: usize, val: *const usize, val_len: usize) !usize {
    const res = syscall(54, sock, level, option_name, @intFromPtr(val), val_len, 0);
    if (res < 0) return error.NetworkError else return @intCast(res);
}

inline fn open(path: [*:0]const u8, flags: usize) !usize {
    const res = syscall(2, @intFromPtr(path), flags, 0, 0, 0, 0);
    if (res < 0) return error.OpenFailed else return @intCast(res);
}

inline fn sendFile(out_fd: usize, in_fd: usize, count: usize) !void {
    var buf: [1024]u8 = undefined;
    var total: usize = 0;
    while (total < count) {
        const read_amount = try read(in_fd, &buf, buf.len);
        if (read_amount == 0) break;
        if (read_amount == -1) return error.NetworkError;
        total += @intCast(read_amount);
        _ = try writeAll(out_fd, &buf, read_amount);
    }
}

inline fn exit(code: u8) noreturn {
    _ = syscall(60, code, 0, 0, 0, 0, 0);
    unreachable;
}

fn getFileSize(fd: usize) !usize {
    const timespec = extern struct {
        tv_sec: c_long,
        tv_nsec: c_long,
    };

    const stat = extern struct {
        st_dev: c_ulong,
        st_ino: c_ulong,
        st_nlink: c_ulong,
        st_mode: c_uint,
        st_uid: c_uint,
        st_gid: c_uint,
        __pad0: c_int,
        st_rdev: c_ulong,
        st_size: c_long,
        st_blksize: c_long,
        st_blocks: c_long,
        st_atim: timespec,
        st_mtim: timespec,
        st_ctim: timespec,
        __reserved: [3]c_long,
    };

    var fd_stats: stat = undefined;

    // Get filesize via fstat
    const res = syscall(5, fd, @intFromPtr(&fd_stats), 0, 0, 0, 0);
    if (res < 0) return error.FileError else return @intCast(fd_stats.st_size);
}

/// General system call function.
fn syscall(number: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) callconv(.C) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (number),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
          [arg5] "{r8}" (arg5),
          [arg6] "{r9}" (arg6),
        : "rcx", "r11", "cc", "memory"
    );
}

fn strnlen(s: [*:0]const u8, comptime max_len: usize) usize {
    for (0..max_len) |i| if (s[i] == 0) return i;
    return 0;
}

/// Convert input string to u16.
fn u16fromString(s: [*:0]const u8) u16 {
    var res: usize = 0;
    for (0..5) |c| {
        if (s[c] == 0) return @intCast(res);
        if (s[c] > '9' or s[c] < '0') return 0;
        res = res * 10 + (s[c] - '0');
    }
    return @intCast(res);
}

/// Converts an isize to its ASCII string representation.
fn itoa(value: isize, buffer: []u8) []const u8 {
    var abs: isize = if (value < 0) -value else value;
    var i = buffer.len;

    while (true) {
        i -= 1;
        buffer[i] = @intCast('0' + @rem(abs, 10));
        abs = @divTrunc(abs, 10);

        if (abs == 0) break;
    }

    if (value < 0) {
        i -= 1;
        buffer[i] = '-';
    }

    return buffer[i..buffer.len];
}

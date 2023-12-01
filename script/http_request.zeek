@load base/protocols/conn
@load base/protocols/http

#features estratte:
# content features (trans_depth, res_bdy_len)

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string){
    local uid: string = c$http$uid;
    local src: addr = c$http$id$orig_h;
    local dst: addr = c$http$id$resp_h;
    local trans_depth: count = c$http$trans_depth;
    local meth: string = c$http$method;
    local url: string = c$http$uri;
    local username: string;
    local password: string;
    local capture_password: bool = c$http$capture_password;
    local req_bdy_len: int = c$http$request_body_len;
    local resp_bdy_len: int = c$http$response_body_len;

    if(!capture_password){
        print fmt("HTTP: %s, %s -> %s, depth: %s, method: %s : %s, No password captured, body_len %s -> %s", uid, src, dst, trans_depth, meth, url, req_bdy_len, resp_bdy_len);
    }else {
        print c$http$username;
        username = c$http$username;
        password = c$http$password;
        print fmt("HTTP: %s, %s -> %s, depth: %s, method: %s : %s, Username: %s, Password: %s, body_len %s -> %s", uid, src, dst, trans_depth, meth, url, username, password, req_bdy_len, resp_bdy_len);
    }
}
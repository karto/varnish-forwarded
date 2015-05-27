// 
// Forwarded rules for Varnish 4
// 
// Author Karto Martin <source@karto.net>
// Copyright (c) 2015 Karto Martin. All Right Reserved.
// License The MIT License
// 

#######################################################################
# Client side

sub forwarded_recv {
    
    ####
    # This is only necessary on the first roundtrip
    #
    if (0 == req.restarts) {
    
        ####
        # Forwarding and nginx requests
        #
        # Forwarding for akamai request
        if (req.http.Via ~ "akamai.net" && req.http.Akamai-Origin-Hop) {
            std.log("vcl_recv: Accepting xff from akamai");
        }
        # Forwarding for direct request. Test client.ip agenst forwarders acl.
        elsif (regsub(client.ip, "", "") != ""+server.ip && # NOT a local ssl request (STRING + IP not possible. server.ip != client.ip)
            req.http.X-Forwarded-For ~ "," && 
            client.ip !~ forwarders_acl) {
            std.log("vcl_recv: Restricting xff to client because "+client.ip+" is not in forwarders_acl");
            set req.http.X-Forwarded-For = client.ip;
        }
        # Forwarding for SSL termination request. Test previous xff agenst forwarders acl.
        elsif (regsub(client.ip, "", "") == ""+server.ip && # Nginx local ssl request (STRING + IP not possible. server.ip == client.ip)
            req.http.X-Forwarded-For ~ ",.*," &&
            std.ip(regsub(req.http.X-Forwarded-For, "^.*,\s*([^,]+?)\s*,[^,]*$", "\1"), "0.0.0.0") !~ forwarders_acl) {
            std.log("vcl_recv: Restricting xff to client from ssl because "+regsub(req.http.X-Forwarded-For, "^.*,\s*([^,]+?)\s*,[^,]*$", "\1")+" is not in forwarders_acl");
            set req.http.X-Forwarded-For = regsub(req.http.X-Forwarded-For, "^.*,\s*([^,]+?\s*,[^,]*)$", "\1");
        }
        # Use buildin xff 
        else {
            std.log("vcl_recv: Accepting xff from request");
        }
        # Set X-Client-IP to the first xff address
        set req.http.X-Client-IP = regsub(req.http.X-Forwarded-For, "^([^,]+?)(:?\s*,.+)?$", "\1");
        if ( ! req.http.X-Forwarded-Proto) {
            set req.http.X-Forwarded-Proto = "http";
        }

    }

}
#sub vcl_pipe {
#}
#sub vcl_pass {
#}
#sub vcl_hash {
#}
#sub vcl_purge {
#}
#sub vcl_hit {
#}
#sub vcl_miss {
#}
#sub vcl_deliver {
#}
#sub vcl_synth {
#}


#######################################################################
# Backend Fetch

#sub vcl_backend_fetch {
#}
#sub vcl_backend_response {
#}
#sub vcl_backend_error {
#}


#######################################################################
# Housekeeping

#sub vcl_init {
#}
#sub vcl_fini {
#}

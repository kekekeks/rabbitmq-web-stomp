%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2012-2013 GoPivotal, Inc.  All rights reserved.
%%

-module(rabbit_ws_sockjs).

-export([init/0]).

-include_lib("rabbitmq_stomp/include/rabbit_stomp.hrl").


%% --------------------------------------------------------------------------

-spec init() -> ok.
init() ->
    Port = get_env(port, 55674),
    HttpsPort = get_env(https_port, 55675),
    SockjsOpts = get_env(sockjs_opts, []) ++ [{logger, fun logger/3}],
    HttpsEnabled = get_env(ssl_enabled, false),
    SslCaCertFile = get_env(ssl_ca_certificate_file, "/etc/rabbitmq/ws_stomp/cacert.pem"),
    SslCertFile = get_env(ssl_certificate_file, "/etc/rabbitmq/ws_stomp/cert.pem"),
    SslKeyFile = get_env(ssl_key_file, "/etc/rabbitmq/ws_stomp/cert.key"),
    SslKeyPassword = get_env(ssl_key_password, ""),
    HttpMaxConnections = get_env(http_max_connections, 1024),
    HttpsMaxConnections = get_env(https_max_connections, 1024),

    SockjsState = sockjs_handler:init_state(
                    <<"/stomp">>, fun service_stomp/3, {}, SockjsOpts),
    VhostRoutes = [{[<<"stomp">>, '...'], sockjs_cowboy_handler, SockjsState}],
    Routes = [{'_',  VhostRoutes}], % any vhost

    rabbit_log:info("rabbit_web_stomp: started on ~s:~w~n",
                    ["0.0.0.0", Port]),
    cowboy:start_listener(http, 100,
                          cowboy_tcp_transport, [{port,     Port}, {max_connections, HttpMaxConnections}],
                          cowboy_http_protocol, [{dispatch, Routes}]),
     if
        HttpsEnabled == true ->
            cowboy:start_listener(https, 100,
                                  cowboy_ssl_transport, [
                                        {port, HttpsPort}, {certfile, SslCertFile},
                                        {keyfile, SslKeyFile}, {password, SslKeyPassword},
                                        {cacertfile, SslCaCertFile}, {max_connections, HttpsMaxConnections}],
                                  cowboy_http_protocol, [{dispatch, Routes}]),
            rabbit_log:info("rabbit_web_stomp: started https on ~s:~w~n",
                    ["0.0.0.0", HttpsPort]);
        true ->
            rabbit_log:info("rabbit_web_stomp:https is disabled")
    end,
    ok.

get_env(Key, Default) ->
    case application:get_env(rabbitmq_web_stomp, Key) of
        undefined -> Default;
        {ok, V}   -> V
    end.


%% Don't print sockjs logs
logger(_Service, Req, _Type) ->
    Req.

%% --------------------------------------------------------------------------

service_stomp(Conn, init, _State) ->
    {ok, _Sup, Pid} = rabbit_ws_sup:start_client({Conn}),
    {ok, Pid};

service_stomp(_Conn, {recv, Data}, Pid) ->
    rabbit_ws_client:sockjs_msg(Pid, Data),
    {ok, Pid};

service_stomp(_Conn, closed, Pid) ->
    rabbit_ws_client:sockjs_closed(Pid),
    ok.

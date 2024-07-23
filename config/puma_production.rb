application_path = "/root/metasploit-framework"
LOGDIR = "/root/viper/Docker/log"
msgrpc_port = 60005
directory application_path
environment 'production'
pidfile "#{application_path}/puma.pid"
stdout_redirect "#{LOGDIR}/puma.log","#{LOGDIR}/puma.log"
rackup '/root/metasploit-framework/msf-json-rpc.ru'
quiet
threads 0, 16
bind "tcp://127.0.0.1:#{msgrpc_port}"
preload_app!
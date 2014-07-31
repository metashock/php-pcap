#
# Cookbook Name:: php-pcap
# Recipe:: default
#
# Copyright 2014, Thorsten Heymann
#

execute "phpize" do
	command "phpize"
	cwd "/vagrant"
end

execute "configure" do
	command "./configure"
	cwd "/vagrant"
end

execute "make" do
	command "make"
	cwd "/vagrant"
end

execute "make install" do
	command "make install"
	cwd "/vagrant"
end

file "write php.ini file" do
	path "/etc/php5/cli/conf.d/99_pcap.ini"
	content "extension=pcap.so"
	action :create
end


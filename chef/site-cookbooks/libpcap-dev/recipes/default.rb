#
# Cookbook Name:: libpcap-dev
# Recipe:: default
#
# Copyright 2014, Thorsten Heymann
#

package "libpcap-dev" do
	action :install
end

user "myuser" do
  supports :manage_home => true
  shell "/bin/bash"
  home "/home/myuser"
  comment "Created by Chef"
  password "myencryptedpassword"
  system true
  provider Chef::Provider::User::Useradd
  action :create
end


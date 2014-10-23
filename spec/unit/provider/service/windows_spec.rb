#
# Author:: Nuo Yan <nuo@opscode.com>
# Author:: Seth Chisamore <schisamo@opscode.com>
# Copyright:: Copyright (c) 2010-2011 Opscode, Inc
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'spec_helper'
require 'mixlib/shellout'

describe Chef::Provider::Service::Windows, "load_current_resource" do
  before(:each) do
    @node = Chef::Node.new
    @events = Chef::EventDispatch::Dispatcher.new
    @run_context = Chef::RunContext.new(@node, {}, @events)
    @new_resource = Chef::Resource::WindowsService.new("chef")
    @provider = Chef::Provider::Service::Windows.new(@new_resource, @run_context)
    @provider.current_resource = Chef::Resource::WindowsService.new("current-chef")
    Object.send(:remove_const, 'Win32') if defined?(Win32)
    Win32 = Module.new
    Win32::Service = Class.new
    Win32::Service::AUTO_START = 0x00000002
    Win32::Service::DEMAND_START = 0x00000003
    Win32::Service::DISABLED = 0x00000004
    Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
      double("StatusStruct", :current_state => "running"))
    Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
      double("ConfigStruct", :start_type => "auto start"))
    Win32::Service.stub(:exists?).and_return(true)
    Win32::Service.stub(:configure).and_return(Win32::Service)

  end

  it "should set the current resources service name to the new resources service name" do
    @provider.load_current_resource
    @provider.current_resource.service_name.should == 'chef'
  end

  it "should return the current resource" do
    @provider.load_current_resource.should equal(@provider.current_resource)
  end

  it "should set the current resources status" do
    @provider.load_current_resource
    @provider.current_resource.running.should be_true
  end

  it "should set the current resources start type" do
    @provider.load_current_resource
    @provider.current_resource.enabled.should be_true
  end

  it "does not set the current resources start type if it is neither AUTO START or DISABLED" do
    Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
      double("ConfigStruct", :start_type => "manual"))
    @provider.load_current_resource
    @provider.current_resource.enabled.should be_nil
  end

  describe Chef::Provider::Service::Windows, "start_service" do
    before(:each) do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
    end

    it "should call the start command if one is specified" do
      @new_resource.start_command "sc start chef"
      @provider.should_receive(:shell_out!).with("#{@new_resource.start_command}").and_return("Starting custom service")
      @provider.start_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should use the built-in command if no start command is specified" do
      Win32::Service.should_receive(:start).with(@new_resource.service_name)
      @provider.start_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should do nothing if the service does not exist" do
      Win32::Service.stub(:exists?).with(@new_resource.service_name).and_return(false)
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      @provider.start_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should do nothing if the service is running" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      @provider.start_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should raise an error if the service is paused" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "paused"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      expect { @provider.start_service }.to raise_error( Chef::Exceptions::Service )
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should wait and continue if the service is in start_pending" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "start pending"),
        double("StatusStruct", :current_state => "start pending"),
        double("StatusStruct", :current_state => "running"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      @provider.start_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should fail if the service is in stop_pending" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stop pending"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      expect { @provider.start_service }.to raise_error( Chef::Exceptions::Service )
      @new_resource.updated_by_last_action?.should be_false
    end

    describe "running as a different account" do
      let(:old_run_as) { @new_resource.run_as }
      let(:old_run_as_password) { @new_resource.run_as_password }

      before {
        @new_resource.run_as(".\\wallace")
        @new_resource.run_as_password("Wensleydale")
      }

      after {
        @new_resource.run_as(old_run_as)
        @new_resource.run_as_password(old_run_as_password)
      }

      it "should call #grant_service_logon if the :run_as and :run_as_password attributes are present" do
        expect(Win32::Service).to receive(:start)
        expect(@provider).to receive(:grant_service_logon).and_return(true)
        @provider.start_service
      end
    end
  end


  describe Chef::Provider::Service::Windows, "stop_service" do

    before(:each) do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"),
        double("StatusStruct", :current_state => "stopped"))
    end

    it "should call the stop command if one is specified" do
      @new_resource.stop_command "sc stop chef"
      @provider.should_receive(:shell_out!).with("#{@new_resource.stop_command}").and_return("Stopping custom service")
      @provider.stop_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should use the built-in command if no stop command is specified" do
      Win32::Service.should_receive(:stop).with(@new_resource.service_name)
      @provider.stop_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should do nothing if the service does not exist" do
      Win32::Service.stub(:exists?).with(@new_resource.service_name).and_return(false)
      Win32::Service.should_not_receive(:stop).with(@new_resource.service_name)
      @provider.stop_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should do nothing if the service is stopped" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:stop).with(@new_resource.service_name)
      @provider.stop_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should raise an error if the service is paused" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "paused"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      expect { @provider.stop_service }.to raise_error( Chef::Exceptions::Service )
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should wait and continue if the service is in stop_pending" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stop pending"),
        double("StatusStruct", :current_state => "stop pending"),
        double("StatusStruct", :current_state => "stopped"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:stop).with(@new_resource.service_name)
      @provider.stop_service
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should fail if the service is in start_pending" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "start pending"))
      @provider.load_current_resource
      Win32::Service.should_not_receive(:stop).with(@new_resource.service_name)
      expect { @provider.stop_service }.to raise_error( Chef::Exceptions::Service )
      @new_resource.updated_by_last_action?.should be_false
    end

    it "should pass custom timeout to the stop command if provided" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"))
      @new_resource.timeout 1
      Win32::Service.should_receive(:stop).with(@new_resource.service_name)
      Timeout.timeout(2) do
        expect { @provider.stop_service }.to raise_error(Timeout::Error)
      end
      @new_resource.updated_by_last_action?.should be_false
    end

  end

  describe Chef::Provider::Service::Windows, "restart_service" do

    it "should call the restart command if one is specified" do
      @new_resource.restart_command "sc restart"
      @provider.should_receive(:shell_out!).with("#{@new_resource.restart_command}")
      @provider.restart_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should stop then start the service if it is running" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
      Win32::Service.should_receive(:stop).with(@new_resource.service_name)
      Win32::Service.should_receive(:start).with(@new_resource.service_name)
      @provider.restart_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should just start the service if it is stopped" do
      Win32::Service.stub(:status).with(@new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
      Win32::Service.should_receive(:start).with(@new_resource.service_name)
      @provider.restart_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should do nothing if the service does not exist" do
      Win32::Service.stub(:exists?).with(@new_resource.service_name).and_return(false)
      Win32::Service.should_not_receive(:stop).with(@new_resource.service_name)
      Win32::Service.should_not_receive(:start).with(@new_resource.service_name)
      @provider.restart_service
      @new_resource.updated_by_last_action?.should be_false
    end

  end

  describe Chef::Provider::Service::Windows, "enable_service" do
    before(:each) do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
    end

    it "should enable service" do
      Win32::Service.should_receive(:configure).with(:service_name => @new_resource.service_name, :start_type => Win32::Service::AUTO_START)
      @provider.enable_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should do nothing if the service does not exist" do
      Win32::Service.stub(:exists?).with(@new_resource.service_name).and_return(false)
      Win32::Service.should_not_receive(:configure)
      @provider.enable_service
      @new_resource.updated_by_last_action?.should be_false
    end
  end

  describe Chef::Provider::Service::Windows, "action_enable" do
    it "does nothing if the service is enabled" do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
      @provider.should_not_receive(:enable_service)
      @provider.action_enable
    end

    it "enables the service if it is not set to automatic start" do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
      @provider.should_receive(:enable_service)
      @provider.action_enable
    end
  end

  describe Chef::Provider::Service::Windows, "action_disable" do
    it "does nothing if the service is disabled" do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
      @provider.should_not_receive(:disable_service)
      @provider.action_disable
    end

    it "disables the service if it is not set to disabled" do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
      @provider.should_receive(:disable_service)
      @provider.action_disable
    end
  end

  describe Chef::Provider::Service::Windows, "disable_service" do
    before(:each) do
      Win32::Service.stub(:config_info).with(@new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
    end

    it "should disable service" do
      Win32::Service.should_receive(:configure)
      @provider.disable_service
      @new_resource.updated_by_last_action?.should be_true
    end

    it "should do nothing if the service does not exist" do
      Win32::Service.stub(:exists?).with(@new_resource.service_name).and_return(false)
      Win32::Service.should_not_receive(:configure)
      @provider.disable_service
      @new_resource.updated_by_last_action?.should be_false
    end
  end

  describe Chef::Provider::Service::Windows, "action_configure_startup" do
    { :automatic => "auto start", :manual => "demand start", :disabled => "disabled" }.each do |type,win32|
      it "sets the startup type to #{type} if it is something else" do
        @new_resource.startup_type(type)
        @provider.stub(:current_start_type).and_return("fire")
        @provider.should_receive(:set_startup_type).with(type)
        @provider.action_configure_startup
      end

      it "leaves the startup type as #{type} if it is already set" do
        @new_resource.startup_type(type)
        @provider.stub(:current_start_type).and_return(win32)
        @provider.should_not_receive(:set_startup_type).with(type)
        @provider.action_configure_startup
      end
    end
  end

  describe Chef::Provider::Service::Windows, "set_start_type" do
    it "when called with :automatic it calls Win32::Service#configure with Win32::Service::AUTO_START" do
      Win32::Service.should_receive(:configure).with(:service_name => @new_resource.service_name, :start_type => Win32::Service::AUTO_START)
      @provider.send(:set_startup_type, :automatic)
    end

    it "when called with :manual it calls Win32::Service#configure with Win32::Service::DEMAND_START" do
      Win32::Service.should_receive(:configure).with(:service_name => @new_resource.service_name, :start_type => Win32::Service::DEMAND_START)
      @provider.send(:set_startup_type, :manual)
    end

    it "when called with :disabled it calls Win32::Service#configure with Win32::Service::DISABLED" do
      Win32::Service.should_receive(:configure).with(:service_name => @new_resource.service_name, :start_type => Win32::Service::DISABLED)
      @provider.send(:set_startup_type, :disabled)
    end

    it "raises an exception when given an unknown start type" do
      expect { @provider.send(:set_startup_type, :fire_truck) }.to raise_error(Chef::Exceptions::ConfigurationError)
    end
  end

  describe "grant_service_logon" do
    let(:username) { "unit_test_user" }
    let(:success_string) { "The task has completed successfully.\r\nSee logfile etc." }
    let(:failure_string) { "Look on my works, ye Mighty, and despair!" }
    let(:command) {
      %Q{secedit.exe /configure /db "secedit.sdb" /cfg "#{@provider.grant_policyfile_name(username)}" /areas USER_RIGHTS SECURITYPOLICY SERVICES /log "#{@provider.grant_logfile_name(username)}"}
    }

    before {
      expect(Mixlib::ShellOut).to receive(:new).with(command).and_call_original
      expect_any_instance_of(Mixlib::ShellOut).to receive(:run_command).and_return(nil)
    }

    after {
      # only needed for the second test.
      ::File.delete(@provider.grant_policyfile_name(username)) rescue nil
      ::File.delete(@provider.grant_logfile_name(username)) rescue nil
    }

    it "calls Mixlib::Shellout with the correct command string" do
      expect_any_instance_of(Mixlib::ShellOut).to receive(:stdout).and_return(success_string)
      expect(@provider.grant_service_logon(username)).to be_true
    end

    it "raises an exception when the grant command fails" do
      expect_any_instance_of(Mixlib::ShellOut).to receive(:stdout).and_return(failure_string)
      expect {@provider.grant_service_logon(username)}.to raise_error(Chef::Exceptions::Service)
    end
  end

  describe "cleaning usernames" do
    it "correctly reformats usernames to create valid filenames" do
      expect(@provider.clean_username_for_path("\\\\problem username/oink.txt")).to eq("_problem_username_oink_txt")
      expect(@provider.clean_username_for_path("boring_username")).to eq("boring_username")
    end

    it "correctly reformats local usernames for the policy file" do
      expect(@provider.canonicalize_local_username(".\\maryann")).to eq("maryann")
      expect(@provider.canonicalize_local_username("maryann")).to eq("maryann")

      expect(@provider.canonicalize_local_username("\\\\maryann")).to eq("\\\\maryann")
      expect(@provider.canonicalize_local_username("mydomain\\\\maryann")).to eq("mydomain\\\\maryann")
    end
  end
end

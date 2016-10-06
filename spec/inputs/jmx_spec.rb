# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/bulk_jmx"
require "logstash/codecs/plain"
require 'stud/temporary'
require "jmx4r"

describe LogStash::Inputs::BulkJmx do

  let(:jmx_config_path) { Stud::Temporary.directory }
  after(:each) do
    FileUtils.remove_dir(jmx_config_path)
  end

  subject { LogStash::Inputs::BulkJmx.new("path" => jmx_config_path)}

  context "#validate_configuration(conf_hash)" do
    #Reference to error messages
    MISSING_CONFIG_PARAMETER = LogStash::Inputs::BulkJmx::MISSING_CONFIG_PARAMETER
    BAD_TYPE_CONFIG_PARAMETER = LogStash::Inputs::BulkJmx::BAD_TYPE_CONFIG_PARAMETER
    BAD_TYPE_QUERY = LogStash::Inputs::BulkJmx::BAD_TYPE_QUERY
    MISSING_QUERY_PARAMETER = LogStash::Inputs::BulkJmx::MISSING_QUERY_PARAMETER
    BAD_TYPE_QUERY_PARAMETER = LogStash::Inputs::BulkJmx::BAD_TYPE_QUERY_PARAMETER

    let(:minimal_config) { {"host"=>"localhost","port"=>1234,"queries" => [] } }

    context "global configuration" do
      it "return [] for valid configuration" do
        #Minimal configuration
        expect(subject.validate_configuration(minimal_config)).to eq([])
        # Re-test with java objects from JrJackson serialization
        if LogStash::Environment.jruby?
          require "java"
          expect(subject.validate_configuration({"host"=>"localhost","port"=>1234,"queries" => java.util.ArrayList.new})).to eq([])
        end
      end

      it "return error message for missing mandatory parameters" do
        expect(subject.validate_configuration({})).to eq([MISSING_CONFIG_PARAMETER % "host", MISSING_CONFIG_PARAMETER % "port", MISSING_CONFIG_PARAMETER % "queries"])
      end

      it "return error message for invalid parameters type" do
        expect(subject.validate_configuration({"host"=>1234,"port"=>1234,"queries" => []})).to eq([BAD_TYPE_CONFIG_PARAMETER % {:param => "host", :expected => String, :actual => Fixnum}])
        expect(subject.validate_configuration({"host"=>"localhost","port"=>"1234","queries" => []})).to eq([BAD_TYPE_CONFIG_PARAMETER % {:param => "port", :expected => Fixnum, :actual => String}])
        expect(subject.validate_configuration({"host"=>"localhost","port"=>1234,"queries" => "my_query"})).to eq([BAD_TYPE_CONFIG_PARAMETER % {:param => "queries", :expected => Enumerable, :actual => String}])
      end
    end

    context "query objects in configuration" do
      it "return [] for valid query message" do
        #Full query object
        minimal_config["queries"] = [{
          "name" => "test",
          "objects" => {
              "java.lang:type=Runtime" => {
                  "time" => "runtime_time"
              }
          }
        }]
        expect(subject.validate_configuration(minimal_config)).to eq([])
      end
      it "return error message for invalid query object type" do
        minimal_config["queries"] = [ "1234" ]
        expect(subject.validate_configuration(minimal_config)).to eq([BAD_TYPE_QUERY % { :index => 0, :expected => Hash, :actual => String }])
      end

      it "return error message for missing mandatory query parameter" do
        minimal_config["queries"] = [ {} ]
        expect(subject.validate_configuration(minimal_config)).to eq([MISSING_QUERY_PARAMETER % ["name",0], MISSING_QUERY_PARAMETER % ["objects",0] ])
      end

      it "return error message for invalid query parameters type" do
        minimal_config["queries"] = [ { "name" => 1234, "objects" => {}} ]
        expect(subject.validate_configuration(minimal_config)).to eq([BAD_TYPE_QUERY_PARAMETER % {:param => "name", :index => 0, :expected => String, :actual => Fixnum} ])

        minimal_config["queries"] = [ { "name" => "1234", "objects" => 1234} ]
        expect(subject.validate_configuration(minimal_config)).to eq([BAD_TYPE_QUERY_PARAMETER % {:param => "objects", :index => 0, :expected => Hash, :actual => Fixnum} ])
      end
    end
  end

  context "establish JMX connection" do
    subject { LogStash::Inputs::BulkJmx.new("path" => jmx_config_path, "nb_thread" => 1, "polling_frequency" => 1)}

    let(:queue) { Queue.new }
    it "pass host/port connection parameters to jmx4r" do
      File.open(File.join(jmx_config_path,"my.config.json"), "wb") { |file|  file.write(<<-EOT)
      {
        "host" : "localhost",
        "port" : 1234,
        "queries": []
      }
      EOT
      }

      expect(JMX::MBean).to receive(:connection).with({
        :host => "localhost",
        :port => 1234,
        :url => nil
      }).and_return(nil)

      subject.register
      Thread.new(subject) { sleep 0.5; subject.close } # force the plugin to exit
      subject.run(queue)
    end

    it "pass custom url in addition of host/port connection parameters to jmx4r" do
      File.open(File.join(jmx_config_path,"my.config.json"), "wb") { |file|  file.write(<<-EOT)
      {
        "host" : "localhost",
        "port" : 1234,
        "url" : "abcdefg",
        "queries": []
      }
      EOT
      }

      expect(JMX::MBean).to receive(:connection).with({
        :host => "localhost",
        :port => 1234,
        :url => "abcdefg"
      }).and_return(nil)

      subject.register
      Thread.new(subject) { sleep 0.5; subject.close } # force the plugin to exit
      subject.run(queue)
    end

    it "pass host/port username/password connection parameters to jmx4r" do
      File.open(File.join(jmx_config_path,"my.config.json"), "wb") { |file|  file.write(<<-EOT)
      {
        "host" : "localhost",
        "port" : 1234,
        "username" : "me",
        "password" : "secret",
        "queries": []
      }
      EOT
      }

      expect(JMX::MBean).to receive(:connection).with({
        :host => "localhost",
        :port => 1234,
        :url => nil,
        :username => "me",
        :password => "secret"
      }).and_return(nil)

      subject.register
      Thread.new(subject) { sleep 0.5; subject.close } # force the plugin to exit
      subject.run(queue)
    end
  end

  class DummyJmxObject
    def initialize(object_name, values)
      @object_name = object_name
      @values = values
    end

    def object_name()
      return @object_name
    end

    def attributes()
      attributes = Hash.new
      @values.keys.each{|v| attributes[v] = v}
      return attributes;
    end

    def send(key)
      return @values[key]
    end
  end

  context "query attributes" do
    subject { LogStash::Inputs::BulkJmx.new("path" => jmx_config_path, "nb_thread" => 1, "polling_frequency" => 1)}

    let(:queue) { Queue.new }
    it "query multiple attributes from multiple objects" do
      File.open(File.join(jmx_config_path,"my.config.json"), "wb") { |file|  file.write(<<-EOT)
      {
        "host" : "localhost",
        "port" : 1234,
        "queries": [{
          "name" : "VitalResourcePoolStats",
          "objects" : {
            "java.lang:type=Runtime" : {
              "mem" : "runtime_mem",
              "cpu" : "runtime_cpu"
            },
            "java.lang:type=Runtime2" : {
              "mem" : "runtime2_mem"
            }
          }
        }]
      }
      EOT
      }

      expect(JMX::MBean).to receive(:connection).with({:host => "localhost", :port => 1234, :url => nil}).and_return(nil)
      expect(JMX::MBean).to receive(:find_all_by_name).with("java.lang:type=Runtime", :connection => nil).and_return(
          [DummyJmxObject.new("java.lang:type=Runtime", {"cpu" => 1, "mem" => "ok"})])
      expect(JMX::MBean).to receive(:find_all_by_name).with("java.lang:type=Runtime2", :connection => nil).and_return(
          [DummyJmxObject.new("java.lang:type=Runtime2", {"cpu" => 2, "mem" => "bad"})])

      subject.register
      Thread.new(subject) { sleep 0.5; subject.close } # force the plugin to exit
      subject.run(queue)

      sleep 0.5

      expect(queue.size).to eq(1)
      event = queue.pop
      expect(event).to be_a LogStash::Event
      expect(event.get('name')).to eq "VitalResourcePoolStats"
      expect(event.get('runtime_mem')).to eq "ok"
      expect(event.get('runtime2_mem')).to eq "bad"
      expect(event.get('runtime_cpu')).to eq 1
    end

    it "query no objects" do
      File.open(File.join(jmx_config_path,"my.config.json"), "wb") { |file|  file.write(<<-EOT)
      {
        "host" : "localhost",
        "port" : 1234,
        "queries": [{
          "name" : "VitalResourcePoolStats",
          "objects" : { }
        }]
      }
      EOT
      }

      expect(JMX::MBean).to receive(:connection).with({:host => "localhost", :port => 1234, :url => nil}).and_return(nil)

      subject.register
      Thread.new(subject) { sleep 0.5; subject.close } # force the plugin to exit
      subject.run(queue)

      sleep 0.5

      expect(queue.size).to eq(1)
      event = queue.pop
      expect(event).to be_a LogStash::Event
      expect(event.get('name')).to eq "VitalResourcePoolStats"
    end
  end

end

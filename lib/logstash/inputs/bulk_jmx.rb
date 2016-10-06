# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/json"

# This input plugin permits to retrieve metrics from remote Java applications using JMX.
# Every `polling_frequency`, it scans a folder containing json configuration 
# files describing JVMs to monitor with metrics to retrieve.
# Then a pool of threads will retrieve metrics and create events.
#
# ## The configuration:
#
# In Logstash configuration, you must set the polling frequency,
# the number of thread used to poll metrics and a directory absolute path containing
# json files with the configuration per jvm of metrics to retrieve.
# Logstash input configuration example:
# [source,ruby]
#     jmx {
#       //Required
#       path => "/apps/logstash_conf/jmxconf"
#       //Optional, default 60s
#       polling_frequency => 15
#       type => "bulk_jmx"
#       //Optional, default 4
#       nb_thread => 4
#     }
#
# Json JMX configuration example:
# [source,js]
#     {
#       //Required, JMX listening host/ip
#       "host" : "192.168.1.2",
#       //Required, JMX listening port
#       "port" : 1335,
#       //Optional, the username to connect to JMX
#       "username" : "user",
#       //Optional, the password to connect to JMX
#       "password": "pass",
#       //Required, list of events with JMX metrics to generate
#       "queries" : [
#       {
#         //Required, the object name of event
#         "name": "jvm_status",
#         //Required, the description of JMX objects and attributes to fetch
#         objects: {
#           //Required, the JMX object selector (name of Mbean to fetch; can contain wildcards)
#           "java.lang:type=Memory": {
#             // JMX attributes of this object, mapped to fields of the generated event
#             "HeapMemoryUsage": "HeapMemoryUsage",
#             "ObjectPendingFinalizationCount": "NotYetFinalizedObjects"
#           },
#           "java.lang:type=Runtime": {
#             "StartTime": "RuntimeStartTime",
#             "VmVendor": "RuntimeVendor"
#           }
#       }]
#     }
#
# Only one event is created on each polling with attributes HeapMemoryUsage, NotYetFinalizedObjects, RuntimeStartTime and
# RuntimeVendor. Wildcards can be used for JMX object selectors. If there are multiple objects that match the wildcard
# selector, what happens depends on whether there is only one selector in the "objects" hash or not:
# - When there are multiple elements in the "objects" hash, like in the previous example, only the first JMX object for each
#   selector is observed and, if any selector matches multiple JMX objects, a warning is issued into the log.
# - When there is only one element in the "objects" hash and its selector matches multiple JMX objects, an event is created
#   for each of them.
#
# Here is an example of a generated event.
# [source,ruby]
#     {
#       "@version" => "1",
#       "@timestamp" => "2014-02-18T20:57:27.688Z",
#       "host" => "192.168.1.2",
#       "type" => "bulk_jmx",
#       "HeapMemoryUsage" => 1234567,
#       "NotYetFinalizedObjects" => 0,
#       "RuntimeStartTime" => 1234567,
#       "RuntimeVendor" => "Dummy Corporation"
#     }
#
class LogStash::Inputs::BulkJmx < LogStash::Inputs::Base
  config_name 'bulk_jmx'

  #Class Var
  attr_accessor :regexp_group_alias_object
  attr_accessor :queue_conf

  # Path where json conf files are stored
  config :path, :validate => :string, :required => true

  # Indicate interval between two jmx metrics retrieval
  # (in s)
  config :polling_frequency, :validate => :number, :default => 60

  # Indicate number of thread launched to retrieve metrics
  config :nb_thread, :validate => :number, :default => 4

  #Error messages
  MISSING_CONFIG_PARAMETER = "Missing parameter '%s'."
  BAD_TYPE_CONFIG_PARAMETER = "Bad type for parameter '%{param}', expecting '%{expected}', found '%{actual}'."
  MISSING_QUERY_PARAMETER = "Missing parameter '%s' in queries[%d]."
  BAD_TYPE_QUERY = "Bad type for queries[%{index}], expecting '%{expected}', found '%{actual}'."
  BAD_TYPE_QUERY_PARAMETER = "Bad type for parameter '%{param}' in queries[%{index}], expecting '%{expected}', found '%{actual}'."
  # Verify that all required parameter are present in the conf_hash
  public
  def validate_configuration(conf_hash)
    validation_errors = []
    #Check required parameters in configuration
    ["host", "port","queries"].each do |param|
      validation_errors << MISSING_CONFIG_PARAMETER % param unless conf_hash.has_key?(param)
    end

    #Validate parameters type in configuration
    {"host" => String, "port" => Fixnum}.each do |param, expected_type|
      if conf_hash.has_key?(param) && !conf_hash[param].instance_of?(expected_type)
        validation_errors << BAD_TYPE_CONFIG_PARAMETER % { :param => param, :expected => expected_type, :actual => conf_hash[param].class }
      end
    end

    if conf_hash.has_key?("queries")
      if !conf_hash["queries"].respond_to?(:each)
        validation_errors << BAD_TYPE_CONFIG_PARAMETER % { :param => 'queries', :expected => Enumerable, :actual => conf_hash['queries'].class }
      else
        conf_hash['queries'].each_with_index do |query,index|
          unless query.respond_to?(:[]) && query.respond_to?(:has_key?)
            validation_errors << BAD_TYPE_QUERY % {:index => index, :expected => Hash, :actual => query.class}
            next
          end
          #Check required parameters in each query
          ["name", "objects"].each do |param|
            validation_errors << MISSING_QUERY_PARAMETER % [param,index] unless query.has_key?(param)
          end
          #Validate parameters type in each query
          {"name" => String}.each do |param, expected_type|
            if query.has_key?(param) && !query[param].instance_of?(expected_type)
              validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => param, :index => index, :expected => expected_type, :actual => query[param].class }
            end
          end

          if query.has_key?('objects') then
            unless query['objects'].respond_to?(:[]) && query['objects'].respond_to?(:has_key?) && query['objects'].respond_to?(:each)
              validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => 'objects', :index => index, :expected => Hash, :actual => query['objects'].class }
            else
              query['objects'].each do |key, attr_mapping|
                unless key.instance_of?(String)
                  validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => "objects[*]", :index => index, :expected => String, :actual => query[param].class }
                end
                unless attr_mapping.respond_to?(:[]) && attr_mapping.respond_to?(:has_key?)
                  validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => "objects['" + key + "']", :index => index, :expected => Hash, :actual => spec_list.class }
                end

                attr_mapping.each do |attr, attr_alias|
                  validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => "objects[*][*]", :index => index, :expected => String, :actual => query[param].class } unless attr.instance_of?(String)
                  validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => "objects[*][*][*]", :index => index, :expected => String, :actual => query[param].class } unless attr_alias.instance_of?(String)
                end
              end
            end
          end
        end
      end
    end
    return validation_errors
  end

  private
  def replace_alias_object(r_alias_object,object_name)
    @logger.debug("Replace ${.*} variables from #{r_alias_object} using #{object_name}")
    group_alias = @regexp_group_alias_object.match(r_alias_object)
    if group_alias
      r_alias_object = r_alias_object.gsub('${'+group_alias[1]+'}',object_name.split(group_alias[1]+'=')[1].split(',')[0])
      r_alias_object = replace_alias_object(r_alias_object,object_name)
    end
    r_alias_object
  end

  private
  def send_event_to_queue(queue, host, name, values)
    @logger.debug('Send event to queue to be processed by filters/outputs')
    event = LogStash::Event.new
    event.set('host', host)
    event.set('type', @type)
    event.set('name', name)

    number_type = [Fixnum, Bignum, Float]
    boolean_type = [TrueClass, FalseClass]

    values.each do |key, value|
      if boolean_type.include?(value.class) then
        value = value ? 1 : 0
      end

      event.set(key, number_type.include?(value.class) ? value : value.to_s)
    end

    decorate(event)
    queue << event
  end

  # Thread function to retrieve metrics from JMX
  private
  def thread_jmx(queue_conf,queue)
    while true
      begin
        @logger.debug('Wait config to retrieve from queue conf')
        thread_hash_conf = queue_conf.pop
        @logger.debug("Retrieve config #{thread_hash_conf} from queue conf")

        @logger.debug('Check if jmx connection need a user/password')
        if thread_hash_conf.has_key?('username') and thread_hash_conf.has_key?('password')
          @logger.debug("Connect to #{thread_hash_conf['host']}:#{thread_hash_conf['port']} with user #{thread_hash_conf['username']}")
          jmx_connection = JMX::MBean.connection :host => thread_hash_conf['host'],
                                                 :port => thread_hash_conf['port'],
                                                 :url => thread_hash_conf['url'],
                                                 :username => thread_hash_conf['username'],
                                                 :password => thread_hash_conf['password']
        else
          @logger.debug("Connect to #{thread_hash_conf['host']}:#{thread_hash_conf['port']}")
          jmx_connection = JMX::MBean.connection :host => thread_hash_conf['host'],
                                                 :port => thread_hash_conf['port'],
                                                 :url => thread_hash_conf['url']
        end

        @logger.debug("Treat queries #{thread_hash_conf['queries']}")
        thread_hash_conf['queries'].each do |query|
          values = {}
          query['objects'].each do |object_name,attr_specs|
            jmx_objects = JMX::MBean.find_all_by_name(object_name, :connection => jmx_connection)
            unless jmx_objects.length > 0
              @logger.warn("No jmx object found for #{object_name}")
            else
              if jmx_objects.length > 1 and query['objects'].length > 1
                @logger.warn("Multiple objects found for #{object_name} and there are multiple queries object names; I am handling only the first resulting object!")
                jmx_objects = [jmx_objects[0]]
              end
              jmx_objects.each do |jmx_object|
                attr_specs.each do |attr_name,attr_alias|
                  begin
                    value = jmx_object.send(attr_name.snake_case)
                  rescue Exception => ex
                    @logger.warn("Failed retrieving metrics for attribute #{attr_name} on object #{jmx_object.object_name}")
                    @logger.warn(ex.message)
                  end
                  if value.instance_of? Java::JavaxManagementOpenmbean::CompositeDataSupport
                    value.each do |subvalue|
                      values[attr_alias + "_" + subvalue.to_s] = value[subvalue]
                    end
                  else
                    values[attr_alias] = value
                  end
                end
              end
            end
          end
          send_event_to_queue(queue, thread_hash_conf['host'], query['name'], values)
        end
        jmx_connection.close
      rescue LogStash::ShutdownSignal
        break #free
      rescue Exception => ex
        @logger.error(ex.message)
        @logger.error(ex.backtrace.join("\n"))
      end
    end
  end

  public
  def register
    require 'thread'
    require 'jmx4r'

    @logger.info("Create queue dispatching JMX requests to threads")
    @queue_conf = Queue.new

    @logger.info("Compile regexp for group alias object replacement")
    @regexp_group_alias_object = Regexp.new('(?:\${(.*?)})+')
  end

  public
  def run(queue)
    begin
      @run_thread = Thread.current

      threads = []
      @logger.info("Initialize #{@nb_thread} threads for JMX metrics collection")
      @nb_thread.times do
        threads << Thread.new { thread_jmx(@queue_conf,queue) }
      end

      while !@interrupted
        @logger.info("Loading configuration files in path", :path => @path)
        Dir.foreach(@path) do |item|
          next if item == '.' or item == '..'
          begin
            file_conf = File.join(@path, item)
            @logger.debug? && @logger.debug("Loading configuration from file", :file => file_conf)
            config_string = File.read(file_conf)
            conf_hash = LogStash::Json.load(config_string)
            validation_errors = validate_configuration(conf_hash)
            if validation_errors.empty?
              @logger.debug? && @logger.debug("Add configuration to the queue", :config => conf_hash)
              @queue_conf << conf_hash
            else
              @logger.warn("Issue with configuration file", :file => file_conf,
                           :validation_errors => validation_errors)
            end
          rescue Exception => ex
            @logger.warn("Issue loading configuration from file", :file => file_conf,
                         :exception => ex.message, :backtrace => ex.backtrace)
          end
        end
        @logger.debug('Wait until the queue conf is empty')
        delta=0
        until @queue_conf.empty?
          @logger.debug("There are still #{@queue_conf.size} messages in the queue conf. Sleep 1s.")
          delta=delta+1
          sleep(1)
        end
        wait_time=@polling_frequency-delta
        if wait_time>0
          @logger.debug("Wait #{wait_time}s (#{@polling_frequency}-#{delta}(seconds wait until queue conf empty)) before to launch again a new jmx metrics collection")
          sleep(wait_time)
        else
          @logger.warn("The time taken to retrieve metrics is more important than the retrieve_interval time set.
                       \nYou must adapt nb_thread, retrieve_interval to the number of jvm/metrics you want to retrieve.")
        end
      end
    rescue LogStash::ShutdownSignal
      #exiting
    rescue Exception => ex
      @logger.error(ex.message)
      @logger.error(ex.backtrace.join("\n"))
    ensure
      threads.each do |thread|
        thread.raise(LogStash::ShutdownSignal) if thread.alive?
      end
    end

  end

  public
  def stop
    @interrupted = true
    @run_thread.raise(LogStash::ShutdownSignal) if @run_thread.alive?
  end # def stop

  public
  def close
    @interrupted = true
  end # def close
end

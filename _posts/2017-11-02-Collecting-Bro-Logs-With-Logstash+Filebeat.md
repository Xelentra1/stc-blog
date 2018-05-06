---
title: "Collecting Bro Logs in Elasticsearch with Logstash+Filebeat"
layout: post
category: howto
tags: logstash bro
---
## Getting Started
I recently completed a project in which I wanted to collect and parse Bro logs with ELK stack. Elasticsearch's powerful querying capabilites and Kibana's visualizations are very useful for making sense of the large quantities of data that Bro can produce in a few hours. Breaking the logs down and parsing them into Elasticsearch increases the usefulness of the data by providing a larger scope of visibility and a way to quickly get a sense of trends and what the network normally looks like. 

The few guides I found (including one on the Elastic website) assumed Logstash would be running on the same host as Bro, but in my case, I wanted one central ELK server and to have Bro logs forwarded to Logstash and then Elasticsearch. 

Filebeat is one of the plugins available for monitoring files. It is typically used to tail syslog and other types of log files, so I figured it would be a good choice for working with Bro logs. 

## Creating Logstash Inputs, Filters, and Outputs

### Input Section

Since the Bro logs would be forwarded to Logstash by Filebeat, the input section of the pipeline uses the beats input plugin. Here the two options set are the host IP and port on which to listen for Filebeat data.

```
input {
  beats {
    host => "localhost"
    port => 5044
  }
}
```

### Filter Section

The filter section is where the real work happens. The filter section is where available filter plugins are used to parse through each message Logstash receives. This is where fields are created and populated. 

Bro logs follow a predicatable format, though fields may be ordered differently between version or based on customizations. Either way, each log includes a definition of each field at the top of the file. By default the fields are space delimited, though custom delimiters can also be set. 

The use of predictable delimiters means we can make use of the `csv` filter plugin. This plugin uses a comma as a delimiter by default, but it also allows you to set a custom delimiter, which is exactly what I needed (my logs use the default space delimited format).

Before getting to any of this though, we have to make sure to ignore the comments included at the beginning of Bro log files. Each filter section begins with this if statement that drops any message beginning with a '#' character.

```
filter {
  #Let's get rid of those header lines; they begin with a hash
  if [message] =~ /^#/ {
    drop { }
  }
```

The next if statement checks the [type] field for the current message being processed and checks for a match against a string. The type field is set by Filebeat according to how we configure it. See the next section for further details on this, but basically, we give each log file being tracked by Filebeat a type name and can then use that apply the correct filter when it comes time for Logstash to parse it.


Once inside one of these blocks, the `csv` plugin block begins. The 'columns' option allows us to define field names in the order they appear. In the example block below, for `conn.log`, we begin with the timestamp field (ts) and proceed until the final field, tunnel_parents. We also define our separator as a space character with `" "`. 

```
#Now, using the csv filter, we can define the Bro log fields
  if [type] == "bro-conn" {
    csv {
      columns => ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"]

      #If you use a custom delimiter, change the following value in between the quotes to your delimiter. Otherwise, insert a literal <tab> in between the two quotes on your logstash system, use a text editor like nano that doesn't convert tabs to spaces.
      separator => "	"
    }
```

That's all that needs to be done to configure the csv plugin! Next, we set the field which will contain the timestamp of the log ('ts') to be interpreted as a date type field using the `date` plugin. Bro logs use Unix time by default, so we use one of the built-in pattern to tell the `date` plugin how the timestamp is formatted.

```
    #Let's convert our timestamp into the 'ts' field, so we can use Kibana features natively
    date {
      match => [ "ts", "UNIX" ]
    }
```

Finally, we use the `mutate` plugin to make some changes to the fields that will be created. This mainly involves renaming the fields since Elasticsearch does not allow period characters in field names. Along the way, we also convert fields that should be interpreted as a integers to the correct type.

```
    mutate {
      convert => [ "id.orig_p", "integer" ]
      convert => [ "id.resp_p", "integer" ]
      convert => [ "trans_depth", "integer" ]
      convert => [ "request_body_len", "integer" ]
      convert => [ "response_body_len", "integer" ]
      convert => [ "status_code", "integer" ]
      convert => [ "info_code", "integer" ]
      rename =>  [ "host", "http_host" ]
      rename =>  [ "id.orig_h", "id_orig_host" ]
      rename =>  [ "id.orig_p", "id_orig_port" ]
      rename =>  [ "id.resp_h", "id_resp_host" ]
      rename =>  [ "id.resp_p", "id_resp_port" ]
    }
``` 

### Output Section

The output section is pretty straight-forward. Once Logstash is done parsing the event, it will send it's output to Elasticsearch using the `elasticsearch` output plugin. Here we configure the address of the Elasticsearch node and a few other settings. 

The option after the hosts list sets the `manage_template` option to false since we will be using a custom template and we don't want Logstash to overwrite our customizations.

The `index` option allows us to define the name of the index to which records from this output should be written. The value given below specifies that indexes will have dynamic names, using the name of the beat plugin taken from the metadata of the event and a daily timestamp. This means a new index will be written for every day. Finally, the `document_type` option uses the [type] value from the event metadata (that is set by our Filebeat configuration) to set the document type.

```
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
```


## Configuring Filebeat

Next, we configure Filebeat to tail the Bro log files and forward new events to Logstash. This file is located at `/etc/filebeat/filebeat.yml` in the deb installation package.

### Prospectors

The prospector section is where the meat of the configuration happens. Here we define the path to the log files which should be monitored and allows us to set some metadata for the event based on where it came from.

The filebeat prospector configuration is simple. See [the docs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-configuration.html) for more details. 

The use of the 'fields' option allows us to create a field called [type] and set it to any string value. This is what give us the ability to know what kind of log we're dealing with once the event gets to Logstash.

```
#=========================== Filebeat prospectors =============================

filebeat.prospectors:

# Each - is a prospector. Most options can be set at the prospector level, so
# you can use different prospectors for various configurations.
# Below are the prospector specific configurations.

# CONN_LOG
- input_type: log
  paths: 
    - "/usr/local/bro/logs/current/conn.log"
  
  fields:
    type: "bro-conn"
  fields_under_root: true
```

### Outputs

Finally, the outputs section of the Filebeat configuration file is where we tell Filebeat the address of our Logstash server. There is an output plugin for Logstash, called with `output.logstash`.

```

#================================ Outputs =====================================
#----------------------------- Logstash output --------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["localhost:5044"]
```

## Updating The Index Template

A part of the process of configuring Filebeat to work with Logstash is pushing the Filebeat index template to Elasticsearch. This includes definition for field mappings and field types. In order to work more effectively with the IP addresses that are pulled from Bro logs, we can make a change to the default Filebeat index template so that fields that contain IP addresses are interpreted as type 'ip'. 

I added the following lines between the "message" and "offset" blocks in the default template:

```
	"id_resp_host": {"type": "ip"},
	"id_orig_host": {"type": "ip"},
``` 

The final file looks like this:

```
{
  "mappings": {
    "_default_": {
      "_all": {
        "enabled": true,
        "norms": {
          "enabled": false
        }
      },
      "dynamic_templates": [
        {
          "template1": {
            "mapping": {
              "doc_values": true,
              "ignore_above": 1024,
              "index": "not_analyzed",
              "type": "{dynamic_type}"
            },
            "match": "*"
          }
        }
      ],
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "message": {
          "type": "string",
          "index": "analyzed"
        },
	"id_resp_host": {"type": "ip"},
	"id_orig_host": {"type": "ip"},
        "offset": {
          "type": "long",
          "doc_values": "true"
        },
        "geoip"  : {
          "type" : "object",
          "dynamic": true,
          "properties" : {
            "location" : { "type" : "geo_point" }
          }
        }
      }
    }
  },
  "settings": {
    "index.refresh_interval": "5s"
  },
  "template": "filebeat-*"
}
```

## Finishing Thoughts

That's it! Using the information above, it's easy to create Logstash pipelines for each type of Bro log you collect and customize them to your needs. I have a [Github repo](https://github.com/mellow-hype/bro-stash) with the Filebeat configuration files and pipelines for 'conn.log', 'dns.log', 'http.log', and 'notice.log' in their default states.

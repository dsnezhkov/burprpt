#!/usr/bin/env ruby

require_relative 'b_reporter'


# This script allows to convert Burp XML report to a useable Text version, reporting on most common fields



if ARGV[0].nil?
  puts "Usage : #{ __FILE__} <burp.xml>" ; exit 5
end


# Usage


# Step 0: (optional) You can manipulate what fields you want to report on by toggling true/false on the keys
# If no guidance is given to the reporter the default is to report all

i_want_to_report_on = {
    name: true,
    severity: true,
    host: true,
    path: true,
    description: true,
    detail: true,
    detailitem: true,
    request: true,
    response: true,
    remediation: true,
    location:  true,
}


# Step 1: Scans the Burp XML file, populates the object model
bs=BReporter.new(ARGV[0])

# Step 2 (a):  Generates report with query rules

# burpreportobject.generate_with_rules(how, options{})
# burpreportobject.generate_with_rules(how)
# Currently the only option is to group the findings by categories

bs.generate_with_rules(:by_category, i_want_to_report_on)



# ----------------- optional/additional --------------------------
# Step 2 (alternative): Return raw data model, useful for further processing.
# Format is in { issue => [issue location object, ...], issue. }
# each issue object will have keys  :name, :severity, :host, :path, :description, :detail, :detailitem, :request, :response, :remediation, :location
# while generate_with_rules allows you to pass in desired properties for a formatted report (or omit them), this method
# returns raw model, and you can weed out what you do not need on your own.

# Example of iterating over collection and dumping scan statistics:
puts "\n\n *** Statistics ***"
bs.raw_by_category.each do |k,v|
  puts "Issue [#{k}] has (#{v.count}) locations"
end

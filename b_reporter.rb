
require 'base64'
require 'nokogiri'


private

class BIssueCollection
  include Enumerable

  def category_rank

  end

  def initialize
    @issues = Array.new
  end

  def each(&block)
    @issues.each(&block)
  end

  def << (issue)
    @issues << issue
  end
end

class BIssue
  attr_accessor :name, :severity, :host, :path, :description, :detail, :detailitem, :request, :response, :remediation, :location
end

public

class BReporter


  def initialize(filename)
    if filename.empty?  then raise ArgumentError, 'Missing Burp Scanner XML Filename' end

    @bopts ||= Hash.new
    @bissues ||= BIssueCollection.new

    @bopts[:fname] = filename

    build_model

  end

  def generate_with_rules(
    rule,
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
    location:  true)


    @bopts[:name] = name
    @bopts[:severity] = severity
    @bopts[:host] = host
    @bopts[:path] = path
    @bopts[:description] = description
    @bopts[:detail] = detail
    @bopts[:detailitem] = detailitem
    @bopts[:request] = request
    @bopts[:response] = response
    @bopts[:remediation] = remediation
    @bopts[:location] = location

    if rule.empty?  then raise ArgumentError, 'Missing Rule <by_category|...>' end
    @bopts[:rule] = rule

    case rule
      when /by_category/
        generate_by_category
      else
        raise ArgumentError, "Rule ( #{rule} ) is not valid"
    end

  end


  def build_model

   @doc=nil

    begin
      @doc = Nokogiri::XML(File.open(@bopts[:fname]))
    rescue Exception => e
      puts $stderr, 'Error processing the Burp XML file : ', e.message
      raise  ScriptError,  'Please make sure Burp XML file is found and can be read'
    end


    begin

      issues=@doc.xpath("//issue")

      issues.each do |issue|

        burp_issue = BIssue.new


        burp_issue.name=issue.xpath("./name").inner_text
        burp_issue.severity=issue.xpath("./severity").inner_text
        burp_issue.host=issue.xpath("./host").inner_text
        burp_issue.path=issue.xpath("./path").inner_text
        burp_issue.description=issue.xpath("./issueBackground").inner_text
        burp_issue.detail=issue.xpath("./issueDetail").inner_text
        burp_issue.detailitem=issue.xpath("./issueDetailItems").inner_text


        burp_issue.request= if issue.xpath("./requestresponse/request[@base64='true']").count.equal?1
                      Base64.decode64(issue.xpath("./requestresponse/request[@base64='true']").inner_text)
                    else
                      issue.xpath("./requestresponse/request[@base64='true']").inner_text
                    end

        burp_issue.response= if issue.xpath("./requestresponse/response[@base64='true']").count.equal?1
                      Base64.decode64(issue.xpath("./requestresponse/response[@base64='true']").inner_text)
                    else
                      issue.xpath("./requestresponse/response[@base64='true']").inner_text
                    end


        burp_issue.remediation =issue.xpath("./remediationBackground").inner_text
        burp_issue.location =issue.xpath("./location").inner_text

        @bissues << burp_issue

      end


    rescue Exception => e
      puts e.message
    end
  end


  def raw_by_category
    @by_category=Hash.new

    @bissues.each do  |bissue|

      if @by_category.has_key?(bissue.name)
        @by_category[bissue.name] << bissue
      else
        @category=Array.new
        @category << bissue
        @by_category[bissue.name]=@category
      end
    end

    return @by_category
  end

  private
  def generate_by_category

    raw_by_category.each do |k,v|

      puts "\n" * 3
      puts "Name: #{k}" if  @bopts[:name].equal?(true)
      puts "\n" * 2
      puts "General Description: #{v[0].description}" if  @bopts[:description].equal?(true)
      puts "\n" * 2
      puts "General Recommendation: #{v[0].remediation}" if  @bopts[:remediation].equal?(true)

      puts

      v.each do |row|
        puts "\n" * 2
        puts "\tLocation : #{row.location}"
        puts "\tSeverity : #{row.severity}" if  @bopts[:severity].equal?(true)
        puts "\tHost : #{row.host}" if  @bopts[:host].equal?(true)
        puts "\tPath : #{row.path}" if  @bopts[:path].equal?(true)
        puts "\tSpecific Details (if any) : \n", fold_lines(2, row.detail) if  @bopts[:detail].equal?(true)
        puts "\tSpecific Detail Items (if any) : \n", fold_lines(2, row.detailitem)  if  @bopts[:detailitem].equal?(true)
        puts "\n\tRequest : \n ", fold_lines(3, row.request) if  @bopts[:request].equal?(true)
        puts "\n\tResponse : \n", fold_lines(3, row.response[0...512]) if  @bopts[:response].equal?(true)
      end


    end


  end

  def fold_lines(indent, str)
    pattern = "\t" *  indent
    str.sub!(/^/, "#{pattern}")
    str.gsub!("\n", "\n#{pattern}")
    str
  end
end
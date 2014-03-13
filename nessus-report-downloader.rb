#!/usr/bin/env ruby
#################################################################################################
# Name: Nessus Report Downloader
# Author: Travis Lee
#
# Version: 1.0
# Last Updated: 3/12/2014
#
# Description:  Interactive script that connects to a specified Nessus server using the
#				Nessus REST API to automate mass report downloads. It has the ability to download
#				multiple or all reports/file types/chapters and save them to a folder of
#				your choosing. This has been tested with Nessus 5.2.5 and *should* work with
#				Nessus 5+, YMMV.
#
#				File types include: .nessus v2, HTML, PDF, CSV, and NBE. 
#
#				Chapter types include: Vulnerabilities By Plugin, Vulnerabilities By Host, 
#				Hosts Summary (Executive), Suggested Remediations, Compliance Check (Executive), 
#				and Compliance Check.
#
# Requires: nokogiri
#
# Usage: ruby ./nessus-report-downloader.rb
#
# Reference: http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf
#
#################################################################################################

require 'net/http'
require 'nokogiri'
require 'fileutils'
require 'io/console'

# This method will download the specified file type from specified reports
def report_download(http, headers, reports, reports_to_dl, filetypes_to_dl, chapters_to_dl, rpath)
	begin
		puts "\r\nDownloading report(s). Please wait..."

		# if all reports are selected
		if reports_to_dl[0].eql?("all")
			reports_to_dl.clear
			# re-init array with all report indexs
			reports.each_with_index do |report,idx|
				reports_to_dl.push(idx)
			end	
		end
		
		# iterate through all the indexes and download the reports
		reports_to_dl.each do |rep|
			filetypes_to_dl.each do |ft|
			
				# different paths if csv or nbe or nessus
				if ft.eql?("csv") or ft.eql?("nbe")
					path = "/file/xslt/?report=#{reports[Integer(rep)].at_xpath("name").text}&xslt=#{ft}.xsl"
				elsif ft.eql?("nessus")
					path = "/file/report/download/?report=#{reports[Integer(rep)].at_xpath("name").text}"
				else
					path = "/chapter?report=#{reports[Integer(rep)].at_xpath("name").text}&format=#{ft}&chapters=#{chapters_to_dl}"
				end
				resp = http.get(path, headers)
			
				if ft.eql?("nessus")
					# replaces any "/" chars with "-" so it doesn't mess up the filename
					fname_temp = (reports[Integer(rep)].at_xpath("readableName").text).gsub("/", "-")
			
					# create final path/filename and write to file
					fname = "#{rpath}/#{fname_temp}-#{reports[Integer(rep)].at_xpath("timestamp").text}.nessus"
					dl_resp = resp
					
				else
					# extract the redirect url
					doc = Nokogiri::HTML(resp.body)
					redirect_url = doc.at('meta[http-equiv="refresh"]')['content'][/url=(.+)/, 1]
				
					# need to wait for the report to finish formatting
					sleep(5)
					dl_resp = http.get(redirect_url, headers)
					while dl_resp.body.include?("<title>Formatting the report</title>") do
						sleep(2)
						dl_resp = http.get(redirect_url, headers)
					end
			
					# if csv, nbe, or pdf, need to go to another url to download
					if ft.eql?("csv") or ft.eql?("nbe") or ft.eql?("pdf")
						dl_resp = http.get("#{redirect_url}&step=2", headers)
					end
				
					# create final path/filename and write to file
					fname_temp = redirect_url.split("=")
					fname = "#{rpath}/#{fname_temp[1]}"
					
				end
				
				# write file
				open(fname, 'w') { |f|
  					f.puts dl_resp.body
  				}
  			
  				puts "Downloading report: #{fname}"
  			end
		end
		
	rescue StandardError => download_report_error
		puts "\r\n\nError downloading report: #{download_report_error}\r\n\n"
		exit
	end
end

# This method will return a list of all the reports on the server
def get_report_list(http, headers, seq)
	begin
		# Try and do stuff
		path = "/report/list"
		resp = http.post(path, 'seq=' + seq, headers)

		# extract event information
		doc = Nokogiri::XML(resp.body)
		root = doc.root
		reports = root.xpath("contents/reports/report")
		puts "Number of reports found: #{reports.count}"
		reports.each_with_index do |report,idx|
			puts "[#{idx}] Name: #{report.at_xpath("readableName").text} | GUID: #{report.at_xpath("name").text} | Status: #{report.at_xpath("status").text}"
		end
		return reports
		
	rescue StandardError => get_report_error
		puts "\r\n\nError getting report list: #{get_report_error}\r\n\n"
		exit
	end
end


# This method will make the initial login request and set the token value to use
def get_token(http, username, password, seq)
	begin
		path = "/login"
		resp = http.post(path, 'password=' + password + '&seq=' + seq + '&login=' + username)

		cookie = resp.response['set-cookie']
		headers = { 
			"User-Agent" => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0',
			"Cookie" => cookie,
			"Accept" => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			"Accept-Language" => 'en-us,en;q=0.5',
			"Accept-Encoding" => 'text/html;charset=UTF-8',
			"Cache-Control" => 'max-age=0'
		 }
		return headers
		
	rescue StandardError => get_token_error
		puts "\r\n\nError logging in/getting token: #{get_token_error}\r\n\n"
		exit
	end
end

### MAIN ###

puts "\r\nNessus Report Downloader 1.0"

# Collect server info
print "\r\nEnter the Nessus Server IP: "
nserver = gets.chomp.to_s
print "Enter the Nessus Server Port [8834]: "
nserverport = gets.chomp.to_s
if nserverport.eql?("")
	nserverport = "8834"
end

# https object
http = Net::HTTP.new(nserver, nserverport)	
http.use_ssl = true				
http.verify_mode = OpenSSL::SSL::VERIFY_NONE	

# Collect user/pass info
print "Enter your Nessus Username: "
username = gets.chomp.to_s
print "Enter your Nessus Password (will not echo): "
password = STDIN.noecho(&:gets).chomp.to_s
seq = "6969"

# login and get token cookie
headers = get_token(http, username, password, seq)

# get list of reports
puts "\r\n\nGetting report list..."
reports = get_report_list(http, headers, seq)
print "Enter the report(s) your want to download (comma separate list) or 'all': "
reports_to_dl = (gets.chomp.to_s).split(",")

if reports_to_dl.count == 0
	puts "\r\nError! You need to choose at least one report!\r\n\n"
	exit
end

# select file types to download
puts "\r\nChoose File Type(s) to Download: "
puts "[0] .nessus - v2 (No chapter selection)"
puts "[1] HTML"
puts "[2] PDF"
puts "[3] CSV (No chapter selection)"
puts "[4] NBE (No chapter selection)"
print "Enter the file type(s) you want to download (comma separate list) or 'all': "
filetypes_to_dl = (gets.chomp.to_s).split(",")

if filetypes_to_dl.count == 0
	puts "\r\nError! You need to choose at least one file type!\r\n\n"
	exit
end

# see which file types to download
formats = []
cSelect = false
filetypes_to_dl.each do |ft|
	case ft
	when "all"
	  formats.push("nessus")
	  formats.push("html")
	  formats.push("pdf")
	  formats.push("csv")
	  formats.push("nbe")
	when "0"
	  formats.push("nessus")
	when "1"
	  formats.push("html")
  	  cSelect = true
	when "2"
	  formats.push("pdf")
	  cSelect = true
	when "3"
	  formats.push("csv")
	when "4"
	  formats.push("nbe")
	end
end

# select chapters to include, only show if html or pdf is in file type selection
chapters = ""
if cSelect
	puts "\r\nChoose Chapter(s) to Include: "
	puts "[0] Vulnerabilities By Plugin"
	puts "[1] Vulnerabilities By Host"
	puts "[2] Hosts Summary (Executive)"
	puts "[3] Suggested Remediations"
	puts "[4] Compliance Check (Executive)"
	puts "[5] Compliance Check"
	print "Enter the chapter(s) you want to include (comma separate list) or 'all': "
	chapters_to_dl = (gets.chomp.to_s).split(",")

	if chapters_to_dl.count == 0
		puts "\r\nError! You need to choose at least one chapter!\r\n\n"
		exit
	end

	# see which chapters to download
	chapters_to_dl.each do |chap|
		case chap
		when "all"
		  chapters << "vuln_hosts_summary;vuln_by_plugin;vuln_by_host;remediations;compliance_exec;compliance;"
		when "0"
		  chapters << "vuln_by_plugin;"
		when "1"
		  chapters << "vuln_by_host;"
		when "2"
		  chapters << "vuln_hosts_summary;"
		when "3"
		  chapters << "remediations;"
		when "4"
		  chapters << "compliance_exec;"
		when "5"
		  chapters << "compliance;"
		end
	end
end

# create report folder
print "\r\nPath to save reports to (without trailing slash): "
rpath = gets.chomp.to_s
unless File.directory?(rpath)
	FileUtils.mkdir_p(rpath)
end

# run report download
if formats.count > 0
	report_download(http, headers, reports, reports_to_dl, formats, chapters, rpath)
end

puts "\r\nReport Download Completed!\r\n\n"
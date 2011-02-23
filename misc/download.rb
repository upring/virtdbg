require 'net/http'

server = "msdl.microsoft.com"
pdb = "ntkrnlmp"
guid = "30092be745b24fe2a311a936e7b7486f2"
uri = "/download/symbols/#{pdb}.pdb/#{guid}/#{pdb}.pd_"
dest = "#{pdb}.pd_"

puts uri

Net::HTTP.start(server) { |http|
    headers = {"User-Agent" => "Microsoft-Symbol-Server/6.6.0007.5"}
    resp = http.get(uri, headers)
    open(dest, "wb") { |file|
        file.write(resp.body)
    }
}
puts "Yay!!"


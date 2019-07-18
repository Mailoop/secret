require 'base64'
require 'openssl'
require 'securerandom'
require 'time'
require 'json'
#require 'clipboard'
class KeySizeTooSmall < StandardError ; end

def main

  result = {}
  rsa_key_pair_password = uuid.gsub("-", "")
  key_pair = gen_key_pair
  cert = certificate(key_pair)

  # Secure RSA KEY PAIR
  #secure_KP = encrypt_and_export_key_pair(key_pair, rsa_key_pair_password )
  #open 'secrets/private.secure.pem', 'w' do |io| io.write secure_KP end
  # Write Cert on Disk
  key_id = uuid
  puts "KeyId"
  puts key_id

  puts ""
  puts "Mscert value"
  ms_cert = ms_der_cert_values(cert)

  puts "azure portal keyCredentials key"
  azure_portal_key_credentials_json = JSON.generate(azure_app_keyCredentials_key(ms_cert[:thumbprint], key_id, ms_cert[:base64_value]))
  #heroku_set_variable("AZURE_PORTAL_KEY_CREDENTIALS", azure_portal_key_credentials_json)
  #to_clipboard("azure portal keyCredentials key")
  #to_clipboard(azure_portal_key_credentials_json)

  result[:azure_portal_key_credentials_json] = azure_portal_key_credentials_json

  puts ""
  puts "X5T_CERT_THUMBPRINT"
  #to_clipboard("X5T_CERT_THUMBPRINT")
  #to_clipboard(ms_cert[:thumbprint])
  result["X5T_CERT_THUMBPRINT"] = ms_cert[:thumbprint]
  
  #Rsa key pair password

  puts ""
  puts "RSA_KEY_PAIR_PASSWORD"
  #to_clipboard("RSA_KEY_PAIR_PASSWORD")
  #to_clipboard(rsa_key_pair_password)
  result["RSA_KEY_PAIR_PASSWORD"] = rsa_key_pair_password


  #base 64 secure pe
  base64_secure_pem = Base64.strict_encode64(encrypt_and_export_key_pair(key_pair, rsa_key_pair_password))
  puts ""
  puts "BASE64_SECURE_PEM"
  #to_clipboard("BASE64_SECURE_PEM")
  #to_clipboard(base64_secure_pem)
  result["BASE64_SECURE_PEM"] = base64_secure_pem
  #puts base64_secure_pem

  `rm cert.der`
  puts "Secret Have been generated"
  #raise KeySizeTooSmall unless key_size >= 2048

  #Checking secret
  puts JSON.pretty_generate(result)
end


def to_clipboard(input)
  Clipboard.copy(input.gsub("\n", ""))
  puts "On Clipboard, press enter to continue"
  gets
end

def key_size
  4096
end

def heroku_set_variable(var_name, value, heroku_app)
  puts ""
  puts var_name.gsub("\n", "")
  puts value.gsub("\n", "")
  puts "heroku set #{var_name} in #{heroku_app}"
  `heroku config:set #{var_name.gsub("\n", "")}=#{value.gsub("\n", "")} -a #{heroku_app} ` if SET_VARIABLE_TO_HEROKU
end

def certificate(key_pair)
  subject = "/O=Wellbee/CN=Mailoop"

  cert = OpenSSL::X509::Certificate.new
  cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
  cert.not_before = Time.now
  cert.not_after = Time.now + 365 * seconds_count_by_day
  cert.public_key = key_pair.public_key
  cert.serial = 0x0
  cert.version = 2
  cert.sign key_pair, OpenSSL::Digest::SHA256.new
  return cert
end

def gen_key_pair
  OpenSSL::PKey::RSA.new(key_size)
end

def decrypt_key_pair(encrypted_rsa_key_pair, password)
  OpenSSL::PKey::RSA.new encrypted_key_pair, password
end

def encrypt_and_export_key_pair(rsa_key_pair, password)
  cipher = OpenSSL::Cipher.new 'AES-256-CBC'
  rsa_key_pair.export cipher, password
end

def uuid
  SecureRandom.uuid
end

def ms_der_cert_values(cert)
  File.open("cert.der", "wb") { |f| f.print cert.to_der }
  thumbprint = `pwsh get_ms_cert_thumbprint.ps1 cert.der`
  value = `pwsh get_ms_cert_value.ps1 cert.der`
  value = value.chars[0..-1].join.gsub("\n", "") # REMOVE THE  last \N
  thumbprint = thumbprint.chars[0..-1].join.gsub("\n", "") # REMOVE THE  last \N
  { thumbprint: thumbprint, base64_value: value}
end

def seconds_count_by_day
  24 * 60 * 60
end


def azure_app_keyCredentials_key(thumbprint, key_id, base64_value)

    {
      "keyId"=> key_id,
      "type"=> "AsymmetricX509Cert",
      "value"=> base64_value,
      "customKeyIdentifier"=> thumbprint,
      "startDate"=> Time.now.utc.iso8601,
      "endDate"=> (Time.now + 360 * seconds_count_by_day ).utc.iso8601,
      "usage"=> "Verify",
    }
end

main
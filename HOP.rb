#  CyberSource Hosted Order Page Library
#
#  Inserts fields into the checkout form for posting data to the CyberSource Hosted Order page
#

require 'openssl'
include OpenSSL

module HOP
  
  ##
  ### HOP Functions
  ##
  ##
  def get_microtime
    t = Time.now
    sprintf("%d%03d", t.to_i, t.usec / 1000)
  end
  
  def hop_hash(data, key)
    Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, key, data)).chomp.gsub(/\n/,'')
  end
  
  def get_merchant_id
    @merchant_id
  end
  
  def get_shared_secret
    @shared_secret
  end
  
  def get_serial_number
    @serial_number
  end
  
  def insert_map_signature(assoc_array)
    assoc_array['mechantID'] = get_merchant_id
    assoc_array['orderPage_timestamp'] = get_microtime
    assoc_array['orderPage_version'] = "4"
    assoc_array['orderPage_serialNumber'] = getSerialNumber
    
    fields = []
    values = ''
    inputs = ''
    assoc_array.each do |key,value|
      fields << key
      values << value
      inputs << '<input type="hidden" name="'+key+'" value="'+value+'">'+"\n"
    end
    
    pub = get_shared_secret
    pub_digest = hop_hash(values,pub)
    inputs << '<input type="hidden" name="orderPage_signaturePublic" value="'+pub_digest+'">'+"\n"
    inputs << '<input type="hidden" name="orderPage_signedFields" value="'+fields+'">'+"\n"
    inputs
  end
  
  def insert_signature(amount="0.00",currency="usd")
    merchant_id = get_merchant_id
    timestamp = get_microtime
    data = merchant_id + amt + curr + timestamp
    serial_number = get_serial_number
    pub_digest = hop_hash(data, get_shared_secret)
    
    sig =  "<input type='hidden' name='amount' value='#{amount}'>\n"
    sig << "<input type='hidden' name='currency' value='#{currency}'>\n"
    sig << "<input type='hidden' name='orderPage_timestamp' value='#{timestamp}'>\n"
    sig << "<input type='hidden' name='merchantID' value='#{merchant_id}'>\n"
    sig << "<input type='hidden' name='orderPage_signaturePublic' value='#{sig_hash}'>\n"
    sig << "<input type='hidden' name='orderPage_version' value='4'>\n"
    sig << "<input type='hidden' name='orderPage_serialNumber' value='#{serial_number}'>\n"
    sig
  end
  
  def insert_signature3(amount="0.00",currency="usd",orderPage_transactionType='sale')
    merchant_id = get_merchant_id
    timestamp = get_microtime
    data = merchant_id + amount + currency + timestamp + orderPage_transactionType
    pub = get_shared_secret
    serial_number = get_serial_number
    pub_digest = hop_hash(data,pub)
    
    sig = "<input type='hidden' name='orderPage_transactionType' value='#{orderPage_transactionType}'>\n"
    sig <<  "<input type='hidden' name='amount' value='#{amount}'>\n"
    sig << "<input type='hidden' name='currency' value='#{currency}'>\n"
    sig << "<input type='hidden' name='orderPage_timestamp' value='#{timestamp}'>\n"
    sig << "<input type='hidden' name='merchantID' value='#{merchant_id}'>\n"
    sig << "<input type='hidden' name='orderPage_signaturePublic' value='#{pub_digest}'>\n"
    sig << "<input type='hidden' name='orderPage_version' value='4'>\n"
    sig << "<input type='hidden' name='orderPage_serialNumber' value='#{serial_number}'>\n"
    sig
  end
  
  def insert_subscription_signature(subscription_amount="0.00",
                                        subscription_start_date="00000000",
                                        subscription_frequency=nil,
                                        subscription_number_of_payments="0",
                                        subscription_automatic_renew="true"
                                        )
    if subscription_frequency.nil? then return end
    
    data = subscription_amount + subscription_start_date + subscription_frequency + subscription_number_of_payments + subscription_automatic_renew
    pub = get_shared_secret
    pub_digest = hop_hash(data, pub)
    sign = '<input type="hidden" name="recurringSubscriptionInfo_amount" value="' + subscriptionAmount + '">' + "\n"
    sig << '<input type="hidden" name="recurringSubscriptionInfo_numberOfPayments" value="' + subscriptionNumberOfPayments + '">' + "\n"
    sig << '<input type="hidden" name="recurringSubscriptionInfo_frequency" value="' + subscriptionFrequency + '">' + "\n"
    sig << '<input type="hidden" name="recurringSubscriptionInfo_automaticRenew" value="' + subscriptionAutomaticRenew + '">' + "\n"
    sig << '<input type="hidden" name="recurringSubscriptionInfo_startDate" value="' + subscriptionStartDate + '">' + "\n"
    sig << '<input type="hidden" name="recurringSubscriptionInfo_signaturePublic" value="' + pub_digest + '">' + "\n"
    sig
  end
  
  def insert_subscription_id_signature(subscription_id)
    if subscription_id.nil? then return end
    
    pub_digest = hop_hash(subscription_id, get_shared_secret)
    str = '<input type="hidden" name="paySubscriptionCreateReply_subscriptionID" value="' + subscription_id + '">' + "\n"
    str << '<input type="hidden" name="paySubscriptionCreateReply_subscriptionIDPublicSignature" value="' + pub_digest + '">' + "\n"
    str
  end
  
  def verify_signature(data,signature)
     pub_digest = hop_hash(data, get_shared_secret)
     pub_digest.eql?(signature)
  end
  
  def verify_transaction_signature(message)
    data = ''
    message['signedFields'].split(',').each do |field|
      data << message[field]
    end
    verify_signature(data,message['transactionSignature'])
  end
  
  # verify_transaction_signature(params)
    
end

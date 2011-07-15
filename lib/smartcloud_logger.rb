class SmartcloudLogger < Logger
  def format_message(severity, timestamp, foobar, message) 
    message = message.to_s 
    
    "#{timestamp.strftime("%b %d %H:%M:%S")} #{severity}: #{message}\n"
  end 

end

##! meterpreter.bro
##!
##! Bro-IDS policy to detect Metasploit's meterpreter payload transfer
##! Note that it does not detect payload transfers over SSL
##!
##! Fox-IT
##! Security Research Team
##!
##! https://github.com/fox-it/bro-scripts

@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        Metasploit::Meterpreter,
    };

    redef record connection += {
        meterpreter_payload_size: count &optional;
    };
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
{
    if(|payload| == 4 && seq == 1)
        {
        c$meterpreter_payload_size = bytestring_to_count(payload, T);
        }
    else if (c?$meterpreter_payload_size && seq == 1 && flags == "AP" && ack > 5)
        {
        if (c$meterpreter_payload_size == ack-5)
            {
            #print( fmt("%DT: Possible Meterpreter Payload transfered! %s:%s -> %s:%s",
            #   c$start_time, c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p));
            NOTICE([$note=Metasploit::Meterpreter, $conn=c, $msg=fmt("Possible Meterpreter Payload transfered!")]);
            }
        }
}

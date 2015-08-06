## meterpreter.bro
##
## Bro-IDS policy to detect Metasploit's meterpreter payload transfer
## Note that it does not detect payload transfers over SSL
##
## Fox-IT
## Security Research Team
##
## https://github.com/fox-it/bro-scripts
## updated by - Brian Kellogg 8/5/2015

export {
    redef enum Notice::Type += { DRC::Meterpreter };

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
            NOTICE([$note=DRC::Meterpreter, $msg="Possible Meterpreter Payload transfered!", $conn=c]);
            }
        }
}



active_sessions = set()

def is_new_session(packet):
    session = (packet.src_ip, packet.dst_ip, packet.dst_port, packet.protocol)

    if session not in active_sessions:
        active_sessions.add(session)
        return True

    return False

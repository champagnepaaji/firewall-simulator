class Packet:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def display(self):
        return (
            f"{self.protocol} packet | "
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port}"
        )


    def __repr__(self):
        return self.display()

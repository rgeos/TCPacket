#!/usr/bin/env python

import click
import threading
from TCPClient import TCPClient
from TCPServer import TCPServer


@click.group()
def cli():
    """
    CLI options for socket connection
    """
    pass


@cli.command()
@click.option(
    "--ip",
    help="The server ip address to bind to",
    default="0.0.0.0",
    type=str,
    show_default=True,
)
@click.option(
    "--port",
    help="The server port number to listen to",
    default=99,
    type=int,
    show_default=True,
)
def server(ip, port):
    """
    Start the server
    """
    click.echo(f"Starting server... {ip}:{port}")
    server = TCPServer(ip, port)
    threading.Thread(target=server.start).start()


@cli.command()
@click.option(
    "--src_ip",
    help="Client's IP address",
    default="127.0.0.1",
    type=str,
    show_default=True,
)
@click.option(
    "--src_port",
    help="Client's port",
    default=99,
    type=int,
    show_default=True,
)
@click.option(
    "--dst_ip",
    help="Server's IP address",
    default="127.0.0.1",
    type=str,
    show_default=True,
)
@click.option(
    "--dst_port",
    help="Server's port",
    default=99,
    type=int,
    show_default=True,
)
@click.option("--test", help="Run 3 way handshake and exit", is_flag=True, default=False, show_default=True)
def client(src_ip, src_port, dst_ip, dst_port, test):
    """
    Start the client
    """
    click.echo(f"Starting client {src_ip}:{src_port} ...")
    click.echo(f"Connecting to {dst_ip}:{dst_port} ...\n")
    client = TCPClient(dst_ip, dst_port)
    if test:
        click.echo(f"Performing a test towards {dst_ip}:{dst_port} ...\n")
        client.test()
    client.run()


if __name__ == "__main__":
    cli()

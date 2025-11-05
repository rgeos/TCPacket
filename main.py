#!/usr/bin/env python
import socket
import threading
from datetime import datetime

import click

from Illustrator import TCPacketIllustrator
from TCPClient import TCPClient
from TCPServer import TCPServer


def get_current_datetime():
    now = datetime.now()
    return now.strftime("%Y_%m_%d_%H_%M_%S")


def get_local_ip():
    """
    Get the local ip address
    """
    local_ip = socket.gethostbyname(socket.gethostname())
    return local_ip


def start_client(src_ip, src_port, dst_ip, dst_port):
    """
    Start the client
    """
    click.echo(f"Starting client {src_ip}:{src_port} ...")
    click.echo(f"Connecting to {dst_ip}:{dst_port} ...\n")
    tcp_client = TCPClient(dst_ip, dst_port)

    return tcp_client


@click.group()
def cli():
    """
    Simple Server/Client application based on TCP socket
    \n
    This application will allow the visualization
    and the creation of data payload on top of a TCP packet
    """
    pass


@cli.group()
def server():
    """
    CLI options for server socket connection
    """
    pass


@server.command()
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
def start(ip, port):
    """
    Start the server
    """
    click.echo(f"Starting server... {ip}:{port}")
    tcp_server = TCPServer(ip, port)
    threading.Thread(target=tcp_server.start).start()


@cli.group()
@click.option(
    "--src_ip",
    help="Client's IP address",
    default=get_local_ip(),
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
@click.pass_context
def client(ctx, src_ip, src_port, dst_ip, dst_port):
    """
    CLI options for client socket connection
    """
    ctx.ensure_object(dict)
    ctx.obj["src_ip"] = src_ip
    ctx.obj["src_port"] = src_port
    ctx.obj["dst_ip"] = dst_ip
    ctx.obj["dst_port"] = dst_port

    click.echo(f"Starting client {src_ip}:{src_port} ...")
    click.echo(f"Connecting to {dst_ip}:{dst_port} ...\n")
    tcp_server = TCPClient(dst_ip, dst_port)
    return tcp_server


@client.command(name="test")
@click.pass_context
def test_data(ctx):
    """Perform a test from client to server"""
    test_client = start_client(
        ctx.obj["src_ip"], ctx.obj["src_port"], ctx.obj["dst_ip"], ctx.obj["dst_port"]
    )
    test_client.send_test_data()


@client.command(name="cli")
@click.pass_context
def cli_data(ctx):
    """Create packages from the CLI and send it to the server"""
    cli_client = start_client(
        ctx.obj["src_ip"], ctx.obj["src_port"], ctx.obj["dst_ip"], ctx.obj["dst_port"]
    )
    cli_client.send_cli_data()


@client.command(name="file")
@click.option("--path", type=click.Path(True), help="File to process", required=True)
@click.pass_context
def file_data(ctx, path):
    """Read data from file, create packages and send it to the server"""
    click.echo(f"Reading file {path}")
    file_client = start_client(
        ctx.obj["src_ip"], ctx.obj["src_port"], ctx.obj["dst_ip"], ctx.obj["dst_port"]
    )
    file_client.file_data(path)


@cli.command()
@click.option("-f", type=click.Path(True), help="Data to process", required=True)
@click.option(
    "-o",
    type=str,
    help="Output file",
    default=f"output_{get_current_datetime()}.xls",
)
def render(f, o):
    """Render the payload structure in Excel"""
    click.echo(f"Rendering illustrator {f} and writing to {o}")
    excel_creator = TCPacketIllustrator(f)
    excel_creator.create_excel(o)


if __name__ == "__main__":
    cli()

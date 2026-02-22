"""
Command-line interface for OFAC Crypto Screener.

Usage:
    python -m ofac_screener update          # Download/update SDN data
    python -m ofac_screener screen <addr>   # Screen a single address
    python -m ofac_screener batch <file>    # Screen addresses from file
    python -m ofac_screener stats           # Show SDN statistics
    python -m ofac_screener api             # Start REST API server
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from .screener import OFACScreener
from .models import Chain

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@click.group()
@click.option("--data-dir", "-d", type=click.Path(), default="./data",
              help="Directory for SDN data cache")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, data_dir: str, verbose: bool):
    """
    OFAC Crypto Screener - Screen cryptocurrency addresses against OFAC SDN List.
    
    This tool helps Virtual Asset Service Providers (VASPs) and compliance teams
    meet their sanctions screening obligations under the Bank Secrecy Act and
    OFAC requirements.
    """
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = Path(data_dir)
    ctx.obj["verbose"] = verbose
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command()
@click.option("--force", "-f", is_flag=True, help="Force re-download")
@click.pass_context
def update(ctx, force: bool):
    """Download or update OFAC SDN data."""
    click.echo("📥 Updating OFAC SDN data...")
    
    screener = OFACScreener(data_dir=ctx.obj["data_dir"])
    
    if screener.update(force=force):
        stats = screener.get_stats()
        click.echo(f"✅ Successfully updated SDN data")
        click.echo(f"   Total entries: {stats.total_entries}")
        click.echo(f"   Crypto addresses: {stats.crypto_addresses}")
        click.echo(f"   Last updated: {stats.last_updated}")
    else:
        click.echo("❌ Failed to update SDN data", err=True)
        sys.exit(1)


@cli.command()
@click.argument("address")
@click.option("--chain", "-c", type=str, default=None,
              help="Blockchain network (BTC, ETH, USDT, etc.)")
@click.option("--no-fuzzy", is_flag=True, help="Disable fuzzy matching")
@click.option("--output", "-o", type=click.Choice(["json", "text"]), default="text",
              help="Output format")
@click.pass_context
def screen(ctx, address: str, chain: Optional[str], no_fuzzy: bool, output: str):
    """Screen a cryptocurrency wallet address."""
    screener = OFACScreener(data_dir=ctx.obj["data_dir"])
    
    chain_enum = None
    if chain:
        try:
            chain_enum = Chain(chain.upper())
        except ValueError:
            click.echo(f"⚠️  Unknown chain: {chain}, will auto-detect", err=True)
    
    result = screener.screen(
        address=address,
        chain=chain_enum,
        include_fuzzy=not no_fuzzy,
    )
    
    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        # Text output
        click.echo(f"\n{'='*60}")
        click.echo(f"🔍 OFAC Screening Result")
        click.echo(f"{'='*60}")
        click.echo(f"Address: {result.address}")
        click.echo(f"Chain: {result.chain.value}")
        click.echo(f"Time: {result.screening_time_ms:.2f}ms")
        click.echo(f"{'='*60}")
        
        if result.match_type.value == "exact":
            click.echo("🚨 EXACT MATCH - CRITICAL RISK")
            click.echo(f"Risk Level: {result.risk_level.value.upper()}")
            for match in result.matched_addresses:
                click.echo(f"\n  Sanctioned Entity: {match.name}")
                click.echo(f"  OFAC UID: {match.uid}")
                click.echo(f"  Program: {match.program}")
        elif result.match_type.value == "fuzzy":
            click.echo("⚠️  FUZZY MATCH - HIGH RISK")
            click.echo(f"Risk Level: {result.risk_level.value.upper()}")
            click.echo(f"Edit Distance: {result.fuzzy_distance}")
            click.echo(f"Confidence: {result.confidence_score:.2%}")
            for match in result.matched_addresses[:3]:
                click.echo(f"\n  Similar to: {match.address}")
                click.echo(f"  Entity: {match.name}")
                click.echo(f"  Program: {match.program}")
        else:
            click.echo("✅ NO MATCH - CLEAR")
            click.echo(f"Risk Level: {result.risk_level.value.upper()}")
        
        click.echo(f"{'='*60}\n")


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--chain", "-c", type=str, default=None, help="Blockchain network")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file (JSON)")
@click.pass_context
def batch(ctx, file: str, chain: Optional[str], output: Optional[str]):
    """Screen multiple addresses from a file (one per line)."""
    screener = OFACScreener(data_dir=ctx.obj["data_dir"])
    
    # Read addresses from file
    addresses = Path(file).read_text().strip().split("\n")
    addresses = [a.strip() for a in addresses if a.strip()]
    
    click.echo(f"📋 Screening {len(addresses)} addresses...")
    
    chain_enum = None
    if chain:
        try:
            chain_enum = Chain(chain.upper())
        except ValueError:
            pass
    
    results = screener.batch_screen(
        addresses=addresses,
        chain=chain_enum,
    )
    
    # Count results
    exact_matches = sum(1 for r in results if r.match_type.value == "exact")
    fuzzy_matches = sum(1 for r in results if r.match_type.value == "fuzzy")
    clear = sum(1 for r in results if r.match_type.value == "no_match")
    
    click.echo(f"\n📊 Results Summary:")
    click.echo(f"   🚨 Exact Matches: {exact_matches}")
    click.echo(f"   ⚠️  Fuzzy Matches: {fuzzy_matches}")
    click.echo(f"   ✅ Clear: {clear}")
    
    # Output results
    if output:
        output_data = [r.to_dict() for r in results]
        Path(output).write_text(json.dumps(output_data, indent=2))
        click.echo(f"\n💾 Results saved to: {output}")
    else:
        # Print flagged addresses
        flagged = [r for r in results if r.match_type.value != "no_match"]
        if flagged:
            click.echo(f"\n🚩 Flagged Addresses:")
            for r in flagged:
                status = "🚨 EXACT" if r.match_type.value == "exact" else "⚠️  FUZZY"
                click.echo(f"   {status}: {r.address}")


@cli.command()
@click.option("--chain", "-c", type=str, default=None, help="Filter by chain")
@click.pass_context
def stats(ctx, chain: Optional[str]):
    """Show SDN statistics."""
    screener = OFACScreener(data_dir=ctx.obj["data_dir"])
    
    try:
        stats = screener.get_stats()
    except RuntimeError:
        click.echo("❌ No SDN data available. Run 'update' first.", err=True)
        sys.exit(1)
    
    click.echo(f"\n📊 OFAC SDN Statistics")
    click.echo(f"{'='*40}")
    click.echo(f"Total SDN Entries: {stats.total_entries:,}")
    click.echo(f"Crypto Addresses: {stats.crypto_addresses:,}")
    click.echo(f"Last Updated: {stats.last_updated}")
    click.echo(f"File Size: {stats.file_size_bytes / 1024 / 1024:.2f} MB")
    
    click.echo(f"\n📈 By Blockchain:")
    for chain_name, count in sorted(stats.by_chain.items(), key=lambda x: -x[1]):
        click.echo(f"   {chain_name}: {count}")
    
    click.echo(f"\n🏛️ By Sanctions Program:")
    for program, count in sorted(stats.by_program.items(), key=lambda x: -x[1])[:10]:
        click.echo(f"   {program}: {count}")


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="API host")
@click.option("--port", "-p", default=8000, type=int, help="API port")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.pass_context
def api(ctx, host: str, port: int, debug: bool):
    """Start the REST API server."""
    from .api import create_app
    
    click.echo(f"🚀 Starting OFAC Crypto Screener API on {host}:{port}")
    
    app = create_app(data_dir=ctx.obj["data_dir"])
    app.run(host=host, port=port, debug=debug)


@cli.command()
@click.argument("query")
@click.option("--by", "-b", type=click.Choice(["name", "program"]), default="name",
              help="Search by name or program")
@click.pass_context
def search(ctx, query: str, by: str):
    """Search sanctioned entities."""
    screener = OFACScreener(data_dir=ctx.obj["data_dir"])
    
    if by == "name":
        results = screener.search_by_name(query)
    else:
        results = screener.search_by_program(query)
    
    if not results:
        click.echo(f"No results found for: {query}")
        return
    
    click.echo(f"\n🔍 Found {len(results)} addresses matching '{query}':\n")
    
    for addr in results[:20]:  # Limit output
        click.echo(f"  Address: {addr.address}")
        click.echo(f"  Chain: {addr.chain.value}")
        click.echo(f"  Entity: {addr.name}")
        click.echo(f"  Program: {addr.program}")
        click.echo(f"  UID: {addr.uid}")
        click.echo()
    
    if len(results) > 20:
        click.echo(f"  ... and {len(results) - 20} more")


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()

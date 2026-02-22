"""
REST API for OFAC Crypto Screener.

Provides HTTP endpoints for sanctions screening of cryptocurrency addresses.
Built with Flask for simplicity and ease of deployment.

Endpoints:
    POST /screen          - Screen a single address
    POST /batch-screen    - Screen multiple addresses
    GET  /sdn/addresses   - List sanctioned crypto addresses
    GET  /sdn/stats       - Get SDN statistics
    GET  /health          - Health check
"""

import logging
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, g
import time

from .screener import OFACScreener
from .models import Chain

logger = logging.getLogger(__name__)


def create_app(data_dir: Optional[Path] = None) -> Flask:
    """
    Create and configure the Flask application.
    
    Args:
        data_dir: Directory for SDN data cache
        
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    
    # Initialize screener
    screener = OFACScreener(data_dir=data_dir)
    
    # Request timing middleware
    @app.before_request
    def start_timer():
        g.start_time = time.time()
    
    @app.after_request
    def add_timing_header(response):
        if hasattr(g, "start_time"):
            elapsed = (time.time() - g.start_time) * 1000
            response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"
        return response
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            "error": "Bad Request",
            "message": str(e.description),
        }), 400
    
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
        }), 500
    
    # Health check
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        try:
            stats = screener.get_stats()
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "sdn_loaded": True,
                "crypto_addresses": stats.crypto_addresses,
            })
        except Exception:
            return jsonify({
                "status": "degraded",
                "timestamp": datetime.utcnow().isoformat(),
                "sdn_loaded": False,
                "message": "SDN data not loaded. Run update first.",
            }), 503
    
    # Screen single address
    @app.route("/screen", methods=["POST"])
    def screen_address():
        """
        Screen a single cryptocurrency address.
        
        Request body:
            {
                "address": "0x1234...",
                "chain": "ETH",  // optional
                "include_fuzzy": true  // optional, default true
            }
        
        Response:
            {
                "address": "0x1234...",
                "chain": "ETH",
                "match_type": "exact|fuzzy|no_match",
                "risk_level": "critical|high|medium|low|clear",
                "confidence_score": 1.0,
                "matched_addresses": [...],
                "screening_time_ms": 5.23
            }
        """
        data = request.get_json()
        
        if not data or "address" not in data:
            return jsonify({
                "error": "Missing required field: address"
            }), 400
        
        address = data["address"]
        chain_str = data.get("chain")
        include_fuzzy = data.get("include_fuzzy", True)
        
        # Parse chain
        chain = None
        if chain_str:
            try:
                chain = Chain(chain_str.upper())
            except ValueError:
                pass
        
        try:
            result = screener.screen(
                address=address,
                chain=chain,
                include_fuzzy=include_fuzzy,
            )
            return jsonify(result.to_dict())
        except RuntimeError as e:
            return jsonify({
                "error": "SDN data not available",
                "message": str(e),
            }), 503
    
    # Batch screen
    @app.route("/batch-screen", methods=["POST"])
    def batch_screen():
        """
        Screen multiple addresses in batch.
        
        Request body:
            {
                "addresses": ["0x1234...", "0x5678..."],
                "chain": "ETH",  // optional
                "include_fuzzy": true  // optional
            }
        
        Response:
            {
                "results": [...],
                "summary": {
                    "total": 10,
                    "exact_matches": 1,
                    "fuzzy_matches": 2,
                    "clear": 7
                }
            }
        """
        data = request.get_json()
        
        if not data or "addresses" not in data:
            return jsonify({
                "error": "Missing required field: addresses"
            }), 400
        
        addresses = data["addresses"]
        
        if not isinstance(addresses, list):
            return jsonify({
                "error": "addresses must be an array"
            }), 400
        
        if len(addresses) > 1000:
            return jsonify({
                "error": "Maximum 1000 addresses per batch"
            }), 400
        
        chain_str = data.get("chain")
        include_fuzzy = data.get("include_fuzzy", True)
        
        chain = None
        if chain_str:
            try:
                chain = Chain(chain_str.upper())
            except ValueError:
                pass
        
        try:
            results = screener.batch_screen(
                addresses=addresses,
                chain=chain,
                include_fuzzy=include_fuzzy,
            )
            
            # Calculate summary
            exact = sum(1 for r in results if r.match_type.value == "exact")
            fuzzy = sum(1 for r in results if r.match_type.value == "fuzzy")
            clear = sum(1 for r in results if r.match_type.value == "no_match")
            
            return jsonify({
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "exact_matches": exact,
                    "fuzzy_matches": fuzzy,
                    "clear": clear,
                }
            })
        except RuntimeError as e:
            return jsonify({
                "error": "SDN data not available",
                "message": str(e),
            }), 503
    
    # Get sanctioned addresses
    @app.route("/sdn/addresses", methods=["GET"])
    def get_addresses():
        """
        Get sanctioned cryptocurrency addresses.
        
        Query params:
            chain: Filter by blockchain (BTC, ETH, etc.)
            limit: Max results (default 100)
            offset: Pagination offset
        
        Response:
            {
                "addresses": [...],
                "total": 500,
                "limit": 100,
                "offset": 0
            }
        """
        chain_str = request.args.get("chain")
        limit = min(int(request.args.get("limit", 100)), 1000)
        offset = int(request.args.get("offset", 0))
        
        chain = None
        if chain_str:
            try:
                chain = Chain(chain_str.upper())
            except ValueError:
                pass
        
        try:
            addresses = screener.get_sanctioned_addresses(chain=chain)
            total = len(addresses)
            
            # Paginate
            addresses = addresses[offset:offset + limit]
            
            return jsonify({
                "addresses": [
                    {
                        "address": a.address,
                        "chain": a.chain.value,
                        "uid": a.uid,
                        "name": a.name,
                        "program": a.program,
                    }
                    for a in addresses
                ],
                "total": total,
                "limit": limit,
                "offset": offset,
            })
        except RuntimeError as e:
            return jsonify({
                "error": "SDN data not available",
                "message": str(e),
            }), 503
    
    # Get statistics
    @app.route("/sdn/stats", methods=["GET"])
    def get_stats():
        """
        Get SDN statistics.
        
        Response:
            {
                "total_entries": 15000,
                "crypto_addresses": 500,
                "by_chain": {"BTC": 150, "ETH": 200, ...},
                "by_program": {"IRAN": 100, "CYBER2": 50, ...},
                "last_updated": "2024-01-15T12:00:00"
            }
        """
        try:
            stats = screener.get_stats()
            return jsonify(stats.to_dict())
        except RuntimeError as e:
            return jsonify({
                "error": "SDN data not available",
                "message": str(e),
            }), 503
    
    # Search endpoint
    @app.route("/search", methods=["GET"])
    def search():
        """
        Search sanctioned entities.
        
        Query params:
            q: Search query
            by: Search by 'name' or 'program' (default: name)
            limit: Max results (default 50)
        """
        query = request.args.get("q", "")
        by = request.args.get("by", "name")
        limit = min(int(request.args.get("limit", 50)), 200)
        
        if not query:
            return jsonify({
                "error": "Missing search query (q parameter)"
            }), 400
        
        try:
            if by == "program":
                results = screener.search_by_program(query)
            else:
                results = screener.search_by_name(query)
            
            return jsonify({
                "query": query,
                "by": by,
                "total": len(results),
                "results": [
                    {
                        "address": a.address,
                        "chain": a.chain.value,
                        "uid": a.uid,
                        "name": a.name,
                        "program": a.program,
                    }
                    for a in results[:limit]
                ]
            })
        except RuntimeError as e:
            return jsonify({
                "error": "SDN data not available",
                "message": str(e),
            }), 503
    
    # Update SDN data
    @app.route("/update", methods=["POST"])
    def update_sdn():
        """
        Trigger SDN data update.
        
        Request body (optional):
            {"force": true}
        """
        data = request.get_json() or {}
        force = data.get("force", False)
        
        try:
            success = screener.update(force=force)
            
            if success:
                stats = screener.get_stats()
                return jsonify({
                    "status": "success",
                    "message": "SDN data updated",
                    "stats": stats.to_dict(),
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": "Failed to update SDN data",
                }), 500
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
            }), 500
    
    return app


# For running directly
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8000, debug=True)

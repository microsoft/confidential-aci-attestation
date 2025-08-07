#!/usr/bin/env python3

import os
from flask import Flask, request
import subprocess
import argparse
from typing import List

def create_app(args):

    app = Flask(__name__)

    def execute_binary(name: str, bin_args: List[str]):
        result = subprocess.run([os.path.join(args.bin_dir, name)] + bin_args, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"


    @app.route('/get_snp_version', methods=['GET'])
    def get_snp_version():
        return execute_binary("get_snp_version", [])


    @app.route('/get_attestation_ccf', methods=['GET'])
    def get_attestation_ccf():
        report_data = request.args.get('report_data', '')
        if report_data:
            report_data = "--report-data " + report_data
        return execute_binary("get_attestation_ccf", report_data.split())

    return app

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Starts a server to make attestation binaries available at runtime"
    )

    parser.add_argument(
        '--bin-dir',
        type=str,
        default='', # Default to binaries being available in the path
        help="Path to directory containing binaries"
    )

    create_app(parser.parse_args()).run(debug=True)
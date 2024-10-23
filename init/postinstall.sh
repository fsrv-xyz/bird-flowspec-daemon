#!/usr/bin/env bash
systemctl daemon-reload
systemctl restart bird-flowspec-daemon || true

# Indexer Contract — Auth Service

This document is the authoritative reference for all data the auth service sends to the indexer service, which makes resources searchable via the [query service](https://github.com/linuxfoundation/lfx-v2-query-service).

**Update this document in the same PR as any change to indexer message construction.**

---

## Summary

The auth service does **not** send any data to the indexer service. No resource types are indexed, and no index documents are expected.

This service is a pure request/reply NATS microservice that provides authentication and user profile operations. There is no write path to the indexer.

---

## Resource Types

_None at this time._

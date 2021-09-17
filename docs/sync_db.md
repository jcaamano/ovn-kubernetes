# Synchronous NB operation for OVN-K

This specification proposes synchronous NB OVSDB operation for OVN-K. 

It is implemented through a new OVN-K specific client that operates exclusively
in-memory in a complete synchronous way for standard NB DB ops using structures
generated from NB schema with libovsdb modelgen and additional information to 
optimize operation.

This new client will have a reconciliation thread that reconciles the in-memory
desired NB DB state with the actual NB DB state using a standard libovsdb client.

This new client will be composed of a base client with a read interface
and single-use single-transaction write clients with a read-write interface 
that will be able to track ongoing non-commited state.

Benefits:

- Increased performance due to IO relegated to it's own specific thread
- Increased performance due to no type conversions operating on cache
- Increased performance due to indexing of our choice
- Increased performance due to cached cross references of objects
- Simplification of code reducing threads and synchronization mechanisms
- Simplification of code removing the need of specific DB synchronization code
  on startup.
- Improved consistency via separate write client that is aware of in-flight
  changes
- Improved error handling due to retry mechanism in the reconciliation process

## Read & Write interfaces

There will be separate read and write interfaces with methods tailored for OVN-K
operation. 

The methods arguments must be based off structures generated from NB schema with
libovsdb modelgen. While the intention is not to keep these structures opaque,
it's best to keep the interface homogeneous and not to translate to it the
knowledge of which of the inner data is relevant for each operation given that
internally any operation can still trigger lookups based on non-indexed data.

## Base Client

Implements the read interface. Holds the cache of desired NB state. Has an additional
interface to start & stop the reconciliation provided a libovsdb client.

## Write Client

This is a single use client build from the base client. Implements the read and the
write interface. Uses it's own cache for ongoing changes and delegates to the base
client cache when needed. It has a commit method that interacts with the base client
to update the base client cache and to record the operations for the reconciliation
thread. Once commit is done the client is locked to be thrown away.

## Cache

Composed of a series of maps. Uses its own UUIDs internally, the models will still
contain a real OVSDB UUID or a named-UUID.

- Main map [type, uuid] -> [model, last update timestamp]
- Index map [type, index] -> uuid
- DB to Internal UUID [id] -> [uuid]
- Referenced-from map [type, uuid] -> {uuid, ...}

The cache interface should be a fairly simple & generic CRUD type. Internally the cache
will know how to operate on the models and populate the maps. A timestamp marks the time
a model was updated in the cache. A deleted model can be flagged with a nil timestamp.

When a model is added to the cache, an internal UUID is generated and added to the main
map with the current timestamp. An index of our choice is added pointing to that UUID.
The named-UUID is added pointing to that UUID. Finally if the model contains references
to other models, the reference map is updated of the UUID of latter pointing to the UUID
of the former.

When a model is updated on the cache the operation is similar to creation updating the
relevan entries on the map.

When a model is deleted, the timestamp is set to nil in the main map and the relevant
information is removed from the other maps.


## Reconciliation

Operates on it's own thread with a libovsdb client and the input is the base
client cache and a bucket of internal uuids pointing to a model on the cache
to be updated on NB DB.

The bucket of uuids to be reconciled is generated from a commit of a write client.
Buckets are timestamped every time they are generated or updated.

There can only be two buckets, one that is being reconciled and one that is pending.
A new commit of a write client will merge the generated bucket with a possible pending
bucket. If the reconciliation of a bucket fails with a recoverable error, the bucket is
merged with the pending bucket.

The reconciliation is triggered by the presence of a pending bucket to reconcile
combined with a backoff mechanism.

If any of the models pointed to in the bucket has a timestamp newer than the
bucket timestamp, reconciliation is aborted and the bucket is merged back with the
pending bucket.

If the reconciliation cannot happen due to a unrecoverable error or on a given
set time, panic.

All the models pointed to by the uuids in a bucket will be operated on in a single
libovsdb transaction. For every uuid, in sequence:

- Find the model & timestamp from base client cache
- If the model timestamp is newer than the bucket timestamp, abort reconciliation.
- If the model does not have a real OVSDB UUID, find the model in the libovsdb cache
  and update UUID in base client cache model
- If the timestamp is nil and there is no entry in the index map for the model,
  aggregate a delete op of the model into the transaction.
- If the model was not found in libovsdb cache, aggregate a create
- If the model was found, aggregate an update (if different?).

Note that using mutations is an exercise left for the future. There is potential to
remove the need for the libovsdb cache which is also an exercise left for the future.

After transact, all unrecoverable errors should panic and all recoverable errors
should be retried via merging the current bucket with the pending bucket.

The result of trasact should be used to update the base client cache models with the
real OVSDB UUIDs for every create operation via cross-referencing the named-UUIDs. 

Deleted models should be removed from the main cache map for every delete operation.

## Dynamics

On startup, the controllers/handlers process existing items and build up the desired NB
state. At the end of startup, reconciliation is started and keeps running.
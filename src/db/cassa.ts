import { Client } from "cassandra-driver";
import {
  CASSANDRA_HOST,
  CASSANDRA_DATACENTER,
  CASSANDRA_KEYSPACE
} from "../config/env";

export const cassandra = new Client({
  contactPoints: [CASSANDRA_HOST || "localhost"],
  localDataCenter: CASSANDRA_DATACENTER || "datacenter1",
  keyspace: CASSANDRA_KEYSPACE

});

export const connectCassandra = async () => {
  try {
    await cassandra.connect();
    console.log("Cassandra Connected");
  } catch (err) {
    console.error("Cassandra Error:", err);
  }
};

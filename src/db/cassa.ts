import { Client } from "cassandra-driver";
import {
  CASSANDRA_HOST,
  CASSANDRA_DATACENTER,
  CASSANDRA_KEYSPACE,
  CASSANDRA_PORT,
  CASSANDRA_USERNAME,
  CASSANDRA_PASSWORD
} from "../config/env";

export const cassandra = new Client({
  contactPoints: [CASSANDRA_HOST || "localhost"],
  localDataCenter: CASSANDRA_DATACENTER || "datacenter1",
  keyspace: CASSANDRA_KEYSPACE,
  protocolOptions: {
    port: Number(CASSANDRA_PORT) || 9042,
  },
  credentials: {
    username: CASSANDRA_USERNAME || "cassandra",
    password: CASSANDRA_PASSWORD || "cassandra",
  },

});

export const connectCassandra = async () => {
  try {
    await cassandra.connect();
    console.log("Cassandra Connected");
  } catch (err) {
    console.error("Cassandra Error:", err);
  }
};

import { Client } from "cassandra-driver";

export const cassandra = new Client({
    contactPoints: [process.env.CASSANDRA_HOST || "localhost"],
    localDataCenter: process.env.CASSANDRA_DATACENTER || "datacenter1",
    keyspace: process.env.CASSANDRA_KEYSPACE

});

export const connectCassandra = async () => {
  try {
    await cassandra.connect();
    console.log("Cassandra Connected");
  } catch (err) {
    console.error("Cassandra Error:", err);
  }
};

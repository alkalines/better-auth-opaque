import { createApi } from "@convex-dev/better-auth";
import { createSchemaAuthOptions } from "../auth";
import schema from "./schema";

export const {
  create,
  findOne,
  findMany,
  updateOne,
  updateMany,
  deleteOne,
  deleteMany,
  consumeOne,
  incrementOne,
} = createApi(schema, createSchemaAuthOptions);

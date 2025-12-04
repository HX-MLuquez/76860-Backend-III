import { fakerES as faker } from "@faker-js/faker";
import { createHash } from "./index.js";
/*
const schema = new mongoose.Schema({
  first_name: {
    type: String,
    required: true,
  },
  last_name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: "user",
  },
  pets: {
    type: [
      {
        _id: {
          type: mongoose.SchemaTypes.ObjectId,
          ref: "Pets",
        },
      },
    ],
    default: [],
  },
  documents: [
    {
      name: { type: String, required: true },
      reference: { type: String, required: true },
    },
  ],
  last_connection: {
    type: Date,
    default: Date.now,
  },
});
*/
export const generateMockUsers = (quantity) => {
  const users = [];
  for (let i = 0; i < quantity; i++) {
    users.push({
      first_name: faker.name.firstName(),
      last_name: faker.name.lastName(),
      email: faker.internet.email(),
      password: createHash(faker.internet.password()),
      role: faker.helpers.arrayElement(["user", "admin"]),
      pets: [
        {
          _id: new mongoose.Types.ObjectId(),
        },
      ],
      documents: [
        {
          name: faker.system.fileName(),
          reference: faker.datatype.uuid(),
        },
      ],
      last_connection: faker.date.recent(),
    });
  }
  return users;
};


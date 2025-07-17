import {
  Field,
  HideField,
  ID,
  ObjectType,
  registerEnumType,
} from '@nestjs/graphql';

export enum Role {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

registerEnumType(Role, { name: 'Role' });

@ObjectType()
export class User {
  @Field(() => ID)
  id: string;

  @Field()
  display_name: string;

  @Field()
  email: string;

  @HideField()
  password: string;

  @Field({ nullable: true })
  refresh_token: string;

  @Field(() => Role)
  role: Role;

  @Field()
  created_at: string;

  @Field()
  updated_at: string;
}

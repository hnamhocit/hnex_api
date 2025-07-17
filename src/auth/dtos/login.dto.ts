import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class LoginDTO {
  @Field()
  email: string;

  @Field()
  password: string;
}

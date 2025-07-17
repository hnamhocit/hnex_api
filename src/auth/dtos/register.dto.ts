import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class RegisterDTO {
  @Field()
  email: string;

  @Field()
  password: string;

  @Field()
  display_name: string;
}

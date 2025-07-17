import { Query, Resolver } from '@nestjs/graphql';
import { UserService } from './user.service';
import { UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { CurrentUser } from '../common/decorators/user.decorator';
import { JwtPayload } from '../common/types/jwtPayload';
import { User } from '../common/models/user.model';

@Resolver('User')
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => User, { name: 'profile', nullable: true })
  @UseGuards(AccessTokenGuard)
  async getProfile(@CurrentUser() user: JwtPayload) {
    return this.userService.getProfile(user.sub);
  }
}

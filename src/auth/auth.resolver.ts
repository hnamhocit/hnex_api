import { Args, Mutation, Resolver } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { Tokens } from '../common/models/tokens.model';
import { LoginDTO } from './dtos/login.dto';
import { RegisterDTO } from './dtos/register.dto';
import { UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { CurrentUser } from '../common/decorators/user.decorator';
import { JwtPayload } from '../common/types/jwtPayload';
import { RefreshTokenGuard } from '../common/guards/refreshToken.guard';

@Resolver('Auth')
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => Tokens, { name: 'login' })
  async login(@Args('loginDTO') data: LoginDTO) {
    return this.authService.login(data);
  }

  @Mutation(() => Tokens, { name: 'register' })
  async register(@Args('registerDTO') data: RegisterDTO) {
    return this.authService.register(data);
  }

  @Mutation(() => Boolean, { name: 'logout' })
  @UseGuards(AccessTokenGuard)
  async logout(@CurrentUser() user: JwtPayload) {
    return this.authService.logout(user.sub);
  }

  @Mutation(() => Tokens, { name: 'refresh' })
  @UseGuards(RefreshTokenGuard)
  async refresh(@CurrentUser() user: JwtPayload & { refreshToken: string }) {
    return this.authService.refresh(user.sub, user.refreshToken);
  }
}

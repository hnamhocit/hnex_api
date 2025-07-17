import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDTO } from './dtos/login.dto';
import { RegisterDTO } from './dtos/register.dto';
import { hash, verify } from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../common/types/jwtPayload';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtAccessService: JwtService,
    private readonly jwtRefreshService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  public async register(data: RegisterDTO) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await hash(data.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: data.email,
        display_name: data.display_name,
        password: hashedPassword,
      },
    });

    const tokens = await this.generateTokens({
      sub: newUser.id,
      role: newUser.role,
    });

    await this.hashTokenAndUpdate(tokens.refresh_token, newUser.id);

    return tokens;
  }

  public async login(data: LoginDTO) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (!existingUser) {
      throw new NotFoundException('User not found');
    }

    const isValidPassword = await verify(existingUser.password, data.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid password');
    }

    const tokens = await this.generateTokens({
      sub: existingUser.id,
      role: existingUser.role,
    });

    await this.hashTokenAndUpdate(tokens.refresh_token, existingUser.id);

    return tokens;
  }

  public async logout(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.refresh_token) {
      throw new UnauthorizedException('Refresh token not found');
    }

    await this.hashTokenAndUpdate(null, user.id);

    return true;
  }

  public async refresh(id: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.refresh_token) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const isValidToken = await verify(user.refresh_token, refreshToken);
    if (!isValidToken) {
      throw new UnauthorizedException('Refresh token not valid');
    }

    const tokens = await this.generateTokens({
      sub: user.id,
      role: user.role,
    });

    await this.hashTokenAndUpdate(tokens.refresh_token, user.id);

    return tokens;
  }

  private async generateTokens(payload: JwtPayload) {
    const [access_token, refresh_token] = await Promise.all([
      await this.jwtAccessService.signAsync(payload),
      await this.jwtRefreshService.signAsync(payload),
    ]);

    return { access_token, refresh_token };
  }

  private async hashTokenAndUpdate(token: string | null, userId: string) {
    let hashedToken: string | null = null;

    if (token) {
      hashedToken = await hash(token);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refresh_token: hashedToken,
      },
    });
  }
}

.class public abstract Landroidx/appcompat/view/menu/gp;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/gp$a;
    }
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/gp;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    invoke-static {}, Landroidx/appcompat/view/menu/gp;->a()Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    const-wide/32 v1, 0xa00000

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/gp$a;->f(J)Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    const/16 v1, 0xc8

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/gp$a;->d(I)Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    const/16 v1, 0x2710

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/gp$a;->b(I)Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    const-wide/32 v1, 0x240c8400

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/gp$a;->c(J)Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    const v1, 0x14000

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/gp$a;->e(I)Landroidx/appcompat/view/menu/gp$a;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/gp$a;->a()Landroidx/appcompat/view/menu/gp;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/gp;->a:Landroidx/appcompat/view/menu/gp;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/gp$a;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/t5$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/t5$b;-><init>()V

    return-object v0
.end method


# virtual methods
.method public abstract b()I
.end method

.method public abstract c()J
.end method

.method public abstract d()I
.end method

.method public abstract e()I
.end method

.method public abstract f()J
.end method

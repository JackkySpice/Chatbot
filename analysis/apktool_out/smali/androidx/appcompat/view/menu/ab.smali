.class public abstract Landroidx/appcompat/view/menu/ab;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/ab$a;,
        Landroidx/appcompat/view/menu/ab$b;,
        Landroidx/appcompat/view/menu/ab$c;
    }
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/ab$b;

.field public static final b:Landroidx/appcompat/view/menu/ab$c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/ab$b;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/ab$b;-><init>(Landroidx/appcompat/view/menu/kj;)V

    sput-object v0, Landroidx/appcompat/view/menu/ab;->a:Landroidx/appcompat/view/menu/ab$b;

    new-instance v0, Landroidx/appcompat/view/menu/ab$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ab$c;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/ab;->b:Landroidx/appcompat/view/menu/ab$c;

    return-void
.end method

.method public static final synthetic a()Landroidx/appcompat/view/menu/ab$c;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/ab;->b:Landroidx/appcompat/view/menu/ab$c;

    return-object v0
.end method

.method public static b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    return-object p0
.end method

.method public static final c(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 2

    instance-of v0, p0, Landroidx/appcompat/view/menu/ab$a;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p0, Landroidx/appcompat/view/menu/ab$a;

    goto :goto_0

    :cond_0
    move-object p0, v1

    :goto_0
    if-eqz p0, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/ab$a;->a:Ljava/lang/Throwable;

    :cond_1
    return-object v1
.end method

.method public static final d(Ljava/lang/Object;)Z
    .locals 0

    instance-of p0, p0, Landroidx/appcompat/view/menu/ab$a;

    return p0
.end method

.method public static final e(Ljava/lang/Object;)Z
    .locals 0

    instance-of p0, p0, Landroidx/appcompat/view/menu/ab$c;

    xor-int/lit8 p0, p0, 0x1

    return p0
.end method

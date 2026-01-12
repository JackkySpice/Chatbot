.class public abstract Landroidx/appcompat/view/menu/mj;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Z

.field public static final b:Landroidx/appcompat/view/menu/rk;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "kotlinx.coroutines.main.delay"

    const/4 v1, 0x0

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/py0;->f(Ljava/lang/String;Z)Z

    move-result v0

    sput-boolean v0, Landroidx/appcompat/view/menu/mj;->a:Z

    invoke-static {}, Landroidx/appcompat/view/menu/mj;->b()Landroidx/appcompat/view/menu/rk;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/mj;->b:Landroidx/appcompat/view/menu/rk;

    return-void
.end method

.method public static final a()Landroidx/appcompat/view/menu/rk;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/mj;->b:Landroidx/appcompat/view/menu/rk;

    return-object v0
.end method

.method public static final b()Landroidx/appcompat/view/menu/rk;
    .locals 2

    sget-boolean v0, Landroidx/appcompat/view/menu/mj;->a:Z

    if-nez v0, :cond_0

    sget-object v0, Landroidx/appcompat/view/menu/lj;->u:Landroidx/appcompat/view/menu/lj;

    return-object v0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/em;->c()Landroidx/appcompat/view/menu/na0;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/qa0;->c(Landroidx/appcompat/view/menu/na0;)Z

    move-result v1

    if-nez v1, :cond_2

    instance-of v1, v0, Landroidx/appcompat/view/menu/rk;

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    check-cast v0, Landroidx/appcompat/view/menu/rk;

    goto :goto_1

    :cond_2
    :goto_0
    sget-object v0, Landroidx/appcompat/view/menu/lj;->u:Landroidx/appcompat/view/menu/lj;

    :goto_1
    return-object v0
.end method

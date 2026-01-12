.class public abstract Landroidx/appcompat/view/menu/js0;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/js0$a;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/js0$a;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/h6$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/h6$b;-><init>()V

    return-object v0
.end method


# virtual methods
.method public abstract b()Landroidx/appcompat/view/menu/ko;
.end method

.method public abstract c()Landroidx/appcompat/view/menu/vo;
.end method

.method public d()[B
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/js0;->e()Landroidx/appcompat/view/menu/n11;

    move-result-object v0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/js0;->c()Landroidx/appcompat/view/menu/vo;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/vo;->b()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/n11;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [B

    return-object v0
.end method

.method public abstract e()Landroidx/appcompat/view/menu/n11;
.end method

.method public abstract f()Landroidx/appcompat/view/menu/z11;
.end method

.method public abstract g()Ljava/lang/String;
.end method

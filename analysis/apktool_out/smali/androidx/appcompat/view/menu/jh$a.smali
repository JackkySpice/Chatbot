.class public abstract Landroidx/appcompat/view/menu/jh$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/jh;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method public static a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/jh$a$a;->n:Landroidx/appcompat/view/menu/jh$a$a;

    invoke-interface {p1, p0, v0}, Landroidx/appcompat/view/menu/jh;->p(Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroidx/appcompat/view/menu/jh;

    :goto_0
    return-object p0
.end method

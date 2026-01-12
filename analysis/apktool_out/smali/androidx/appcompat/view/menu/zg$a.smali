.class public abstract Landroidx/appcompat/view/menu/zg$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/zg;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method public static a(Landroidx/appcompat/view/menu/zg;Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Landroidx/appcompat/view/menu/i;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    check-cast p1, Landroidx/appcompat/view/menu/i;

    invoke-interface {p0}, Landroidx/appcompat/view/menu/jh$b;->getKey()Landroidx/appcompat/view/menu/jh$c;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/i;->a(Landroidx/appcompat/view/menu/jh$c;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1, p0}, Landroidx/appcompat/view/menu/i;->b(Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p0

    instance-of p1, p0, Landroidx/appcompat/view/menu/jh$b;

    if-eqz p1, :cond_0

    move-object v1, p0

    :cond_0
    return-object v1

    :cond_1
    sget-object v0, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    if-ne v0, p1, :cond_2

    const-string p1, "null cannot be cast to non-null type E of kotlin.coroutines.ContinuationInterceptor.get"

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_2
    move-object p0, v1

    :goto_0
    return-object p0
.end method

.method public static b(Landroidx/appcompat/view/menu/zg;Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Landroidx/appcompat/view/menu/i;

    if-eqz v0, :cond_1

    check-cast p1, Landroidx/appcompat/view/menu/i;

    invoke-interface {p0}, Landroidx/appcompat/view/menu/jh$b;->getKey()Landroidx/appcompat/view/menu/jh$c;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/i;->a(Landroidx/appcompat/view/menu/jh$c;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1, p0}, Landroidx/appcompat/view/menu/i;->b(Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p1

    if-eqz p1, :cond_0

    sget-object p0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_0
    return-object p0

    :cond_1
    sget-object v0, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    if-ne v0, p1, :cond_2

    sget-object p0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_2
    return-object p0
.end method

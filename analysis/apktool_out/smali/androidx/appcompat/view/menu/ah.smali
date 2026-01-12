.class public abstract Landroidx/appcompat/view/menu/ah;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "completion"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/y50;->a(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    invoke-static {p0}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    sget-object p1, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {p1}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    return-void
.end method

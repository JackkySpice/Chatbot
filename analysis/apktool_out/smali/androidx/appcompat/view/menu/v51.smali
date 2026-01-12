.class public abstract Landroidx/appcompat/view/menu/v51;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/x51;)Landroidx/appcompat/view/menu/fi;
    .locals 1

    const-string v0, "owner"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Landroidx/lifecycle/e;

    if-eqz v0, :cond_0

    check-cast p0, Landroidx/lifecycle/e;

    invoke-interface {p0}, Landroidx/lifecycle/e;->b()Landroidx/appcompat/view/menu/fi;

    move-result-object p0

    goto :goto_0

    :cond_0
    sget-object p0, Landroidx/appcompat/view/menu/fi$a;->b:Landroidx/appcompat/view/menu/fi$a;

    :goto_0
    return-object p0
.end method

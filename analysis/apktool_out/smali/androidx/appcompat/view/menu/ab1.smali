.class public final Landroidx/appcompat/view/menu/ab1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/cg0;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/xy0;

.field public final synthetic b:Landroidx/appcompat/view/menu/cb1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/cb1;Landroidx/appcompat/view/menu/xy0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ab1;->b:Landroidx/appcompat/view/menu/cb1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ab1;->a:Landroidx/appcompat/view/menu/xy0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/vy0;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/ab1;->b:Landroidx/appcompat/view/menu/cb1;

    invoke-static {p1}, Landroidx/appcompat/view/menu/cb1;->a(Landroidx/appcompat/view/menu/cb1;)Ljava/util/Map;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ab1;->a:Landroidx/appcompat/view/menu/xy0;

    invoke-interface {p1, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

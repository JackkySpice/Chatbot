.class public final synthetic Landroidx/appcompat/view/menu/nq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ar0$b;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ar0;

.field public final synthetic b:Ljava/util/Map;

.field public final synthetic c:Landroidx/appcompat/view/menu/yb$a;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ar0;Ljava/util/Map;Landroidx/appcompat/view/menu/yb$a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/nq0;->a:Landroidx/appcompat/view/menu/ar0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/nq0;->b:Ljava/util/Map;

    iput-object p3, p0, Landroidx/appcompat/view/menu/nq0;->c:Landroidx/appcompat/view/menu/yb$a;

    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/nq0;->a:Landroidx/appcompat/view/menu/ar0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/nq0;->b:Ljava/util/Map;

    iget-object v2, p0, Landroidx/appcompat/view/menu/nq0;->c:Landroidx/appcompat/view/menu/yb$a;

    check-cast p1, Landroid/database/Cursor;

    invoke-static {v0, v1, v2, p1}, Landroidx/appcompat/view/menu/ar0;->H(Landroidx/appcompat/view/menu/ar0;Ljava/util/Map;Landroidx/appcompat/view/menu/yb$a;Landroid/database/Cursor;)Landroidx/appcompat/view/menu/yb;

    move-result-object p1

    return-object p1
.end method

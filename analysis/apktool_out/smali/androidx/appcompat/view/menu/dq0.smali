.class public final synthetic Landroidx/appcompat/view/menu/dq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ar0$b;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ar0;

.field public final synthetic b:Ljava/lang/String;

.field public final synthetic c:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ar0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/dq0;->a:Landroidx/appcompat/view/menu/ar0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/dq0;->b:Ljava/lang/String;

    iput-object p3, p0, Landroidx/appcompat/view/menu/dq0;->c:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/dq0;->a:Landroidx/appcompat/view/menu/ar0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/dq0;->b:Ljava/lang/String;

    iget-object v2, p0, Landroidx/appcompat/view/menu/dq0;->c:Ljava/lang/String;

    check-cast p1, Landroid/database/sqlite/SQLiteDatabase;

    invoke-static {v0, v1, v2, p1}, Landroidx/appcompat/view/menu/ar0;->E(Landroidx/appcompat/view/menu/ar0;Ljava/lang/String;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
